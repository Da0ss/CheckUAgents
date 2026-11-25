"""OpenRouter agent adapter (OpenAI-compatible Chat Completions, manual tool loop).

Stdlib only. The loop is manual so the harness records every tool call; the
tools are simulated by the sandbox.

Credentials: pass `api_key` or set OPENROUTER_API_KEY.
The HTTP transport is injectable for tests: `post(url, headers, body) -> (status, headers, body_bytes)`.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from ..models import AgentResponse
from ..sandbox import ToolBox

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "nvidia/nemotron-3.5-super-vl:free"
BACKOFF = (2, 4, 8, 16, 30)  # seconds before retry 1..5
MAX_RETRY_AFTER = 300.0  # never sleep longer than this on a server hint

Transport = Callable[[str, dict, bytes], tuple]


class OpenRouterError(RuntimeError):
    """The API returned an error that retries did not (or cannot) fix."""


def _urllib_post(timeout: float) -> Transport:
    def post(url: str, headers: dict, body: bytes):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
                return resp.status, dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as exc:
            # Non-2xx: hand status and body back; the retry logic decides.
            return exc.code, dict(exc.headers.items()) if exc.headers else {}, exc.read() or b""

    return post


def to_openai_tools(specs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Anthropic-format tool specs (name, description, input_schema) -> OpenAI function tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": s["name"],
                "description": s.get("description", ""),
                "parameters": s.get("input_schema") or {"type": "object", "properties": {}},
            },
        }
        for s in specs
    ]


def _retry_after(headers: dict) -> float | None:
    for k, v in (headers or {}).items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, min(float(v), MAX_RETRY_AFTER))
            except (TypeError, ValueError):
                return None  # HTTP-date form: fall back to the backoff schedule
    return None


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # content parts
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
    return ""


def _add_usage(total: dict, usage: dict) -> None:
    for k, v in usage.items():
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            total[k] = total.get(k, 0) + v
        elif isinstance(v, dict):
            _add_usage(total.setdefault(k, {}), v)


def _error_message(err: Any) -> str:
    if isinstance(err, dict):
        msg = err.get("message") or json.dumps(err)
        code = err.get("code")
        return f"{code}: {msg}" if code is not None else str(msg)
    return str(err)


class OpenRouterAgent:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: str | None = None,
        reasoning: bool = False,
        max_turns: int = 6,
        max_retries: int = 5,
        timeout: float = 120.0,
        min_interval: float = 0.0,
        post: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        url: str = API_URL,
    ):
        key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise RuntimeError("OpenRouter API key missing: set OPENROUTER_API_KEY or pass api_key")
        self._key = key
        self.model = model
        self.reasoning = reasoning
        self.max_turns = max_turns
        self.max_retries = max_retries
        self.timeout = timeout
        self.min_interval = max(0.0, float(min_interval or 0.0))
        self.url = url
        self._post = post or _urllib_post(timeout)
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.Lock()  # min_interval is shared across Runner workers
        self._last_request: float | None = None
        self.name = f"openrouter:{model}"

    # ------------------------------------------------------------ transport
    def _throttle(self) -> None:
        if not self.min_interval:
            return
        with self._lock:
            now = self._clock()
            if self._last_request is not None:
                wait = self._last_request + self.min_interval - now
                if wait > 0:
                    self._sleep(wait)
                    now = self._clock()
            self._last_request = now

    def _request(self, payload: dict) -> dict:
        headers = {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"}
        body = json.dumps(payload).encode()
        last_error = ""
        for attempt in range(self.max_retries + 1):
            self._throttle()
            retry_hint = None
            try:
                status, resp_headers, raw = self._post(self.url, headers, body)
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
                last_error = f"connection error: {type(exc).__name__}: {exc}"
            else:
                if 200 <= status < 300:
                    try:
                        data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise OpenRouterError(f"invalid JSON in response: {exc}") from exc
                    if isinstance(data, dict) and data.get("error"):
                        raise OpenRouterError(f"API error: {_error_message(data['error'])}")
                    return data
                detail = raw.decode("utf-8", "replace")[:500] if isinstance(raw, bytes) else str(raw)[:500]
                last_error = f"HTTP {status}: {detail}"
                if status != 429 and status < 500:
                    raise OpenRouterError(last_error)  # 4xx: retrying will not help
                retry_hint = _retry_after(resp_headers)
            if attempt == self.max_retries:
                break
            delay = retry_hint if retry_hint is not None else BACKOFF[min(attempt, len(BACKOFF) - 1)]
            self._sleep(delay)
        raise OpenRouterError(f"request failed after {self.max_retries + 1} attempts: {last_error}")

    # ------------------------------------------------------------ agent loop
    def run(self, system: str, user_message: str, tools: ToolBox) -> AgentResponse:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ]
        oa_tools = to_openai_tools(tools.specs)
        texts: list[str] = []
        refused = False
        finish_reason = None
        usage: dict[str, Any] = {}
        notes: list[str] = []
        served_by = None

        for _ in range(self.max_turns):
            payload: dict[str, Any] = {"model": self.model, "messages": messages, "tools": oa_tools}
            if self.reasoning:
                payload["reasoning"] = {"enabled": True}
            data = self._request(payload)
            if isinstance(data.get("usage"), dict):
                _add_usage(usage, data["usage"])
            served_by = data.get("model", served_by)
            choices = data.get("choices") or []
            if not choices:
                raise OpenRouterError("response has no choices")
            choice = choices[0]
            if choice.get("error"):
                raise OpenRouterError(f"API error: {_error_message(choice['error'])}")
            finish_reason = choice.get("finish_reason")
            message = choice.get("message") or {}
            text = _text_of(message.get("content"))
            if text:
                texts.append(text)

            if finish_reason == "content_filter":
                refused = True
                break
            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                break

            # Append as returned: reasoning_details must go back unmodified.
            messages.append(message)
            for tc in tool_calls:
                fn = tc.get("function") or {}
                name = fn.get("name", "")
                raw_args = fn.get("arguments")
                if isinstance(raw_args, dict):
                    args = raw_args
                elif not raw_args:
                    args = {}
                else:
                    try:
                        args = json.loads(raw_args)
                    except (TypeError, ValueError):
                        args = None
                    if not isinstance(args, dict):
                        notes.append(f"bad JSON arguments for tool '{name}': {str(raw_args)[:200]}")
                        args = {}
                output = tools.call(name, args)
                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": output})

        meta: dict[str, Any] = {"model": self.model, "served_by": served_by, "finish_reason": finish_reason}
        if usage:
            meta["usage"] = usage
        if notes:
            meta["notes"] = notes
        return AgentResponse(text="\n".join(texts), tool_calls=list(tools.trace), refused=refused, meta=meta)
