"""Claude agent adapter (Anthropic Messages API, manual tool loop).

The loop is manual on purpose: the harness must see and record every tool
call, and the tools are simulated by the sandbox.

Credentials: the SDK reads ANTHROPIC_API_KEY (or an `ant auth login` profile).
"""

from __future__ import annotations

from ..models import AgentResponse
from ..sandbox import ToolBox

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ClaudeAgent:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        effort: str | None = None,
        max_turns: int = 6,
        max_tokens: int = 16000,
        use_fallbacks: bool = True,
        client=None,
    ):
        if client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError("Install the SDK: pip install 'injectbench[claude]'") from exc
            client = anthropic.Anthropic()
        self.client = client
        self.model = model
        self.effort = effort
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.use_fallbacks = use_fallbacks
        self.name = f"claude:{model}"

    def _create(self, **params):
        if self.effort:
            params["output_config"] = {"effort": self.effort}
        if self.use_fallbacks:
            # Server-side fallback: if a safety classifier declines, the API
            # retries the same request on a fallback model inside the same call.
            return self.client.beta.messages.create(
                betas=[FALLBACK_BETA], fallbacks="default", **params
            )
        return self.client.messages.create(**params)

    def run(self, system: str, user_message: str, tools: ToolBox) -> AgentResponse:
        messages = [{"role": "user", "content": user_message}]
        texts: list[str] = []
        refused = False
        stop_reason = None
        served_by = None

        for _ in range(self.max_turns):
            response = self._create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                tools=tools.specs,
                messages=messages,
            )
            stop_reason = response.stop_reason
            served_by = response.model
            texts.extend(b.text for b in response.content if b.type == "text")

            if stop_reason == "refusal":
                refused = True
                break
            if stop_reason == "pause_turn":
                messages.append({"role": "assistant", "content": response.content})
                continue
            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if stop_reason != "tool_use" or not tool_uses:
                break

            messages.append({"role": "assistant", "content": response.content})
            results = []
            for block in tool_uses:
                output = tools.call(block.name, dict(block.input or {}))
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": output})
            # All results of one turn go back in a single user message.
            messages.append({"role": "user", "content": results})

        return AgentResponse(
            text="\n".join(texts),
            tool_calls=list(tools.trace),
            refused=refused,
            meta={"stop_reason": stop_reason, "served_by": served_by},
        )
