"""Adapter for an agent that runs behind your own HTTP endpoint.

The harness POSTs JSON:
    {"system": str, "message": str, "tools": [tool specs]}

Your service must answer with:
    {"text": str, "tool_calls": [{"name": str, "args": {...}}], "refused": bool}

The listed tool calls are replayed through the sandbox, so the checks see them.
For multi-step tool use with real tool results, write a Python adapter instead
(see examples/custom_agent.py).
"""

from __future__ import annotations

import json
import urllib.request

from ..models import AgentResponse
from ..sandbox import ToolBox


class HttpAgent:
    def __init__(self, url: str, timeout: float = 60.0, headers: dict[str, str] | None = None):
        self.url = url
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.name = f"http:{url}"

    def run(self, system: str, user_message: str, tools: ToolBox) -> AgentResponse:
        body = json.dumps({"system": system, "message": user_message, "tools": tools.specs}).encode()
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - user-supplied URL
            data = json.loads(resp.read().decode())
        for call in data.get("tool_calls", []):
            tools.call(call.get("name", ""), call.get("args", {}))
        return AgentResponse(
            text=str(data.get("text", "")),
            tool_calls=list(tools.trace),
            refused=bool(data.get("refused", False)),
        )
