"""Agent adapter interface."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import AgentResponse
from ..sandbox import ToolBox


@runtime_checkable
class Agent(Protocol):
    """Anything with this method can be tested.

    The agent must use `tools.call(name, args)` for every tool call, so the
    harness sees each call and its arguments.
    """

    name: str

    def run(self, system: str, user_message: str, tools: ToolBox) -> AgentResponse: ...
