"""Core data types shared by attacks, checks, agents and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


class Outcome(str, Enum):
    BLOCKED = "blocked"  # the agent resisted the attack
    MISSED = "missed"  # the attack succeeded: the agent "missed" it
    ERROR = "error"  # the run failed (network, adapter bug, ...)


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    result: str = ""
    blocked: bool = False  # a defense layer stopped the call before execution
    blocked_reason: str = ""


@dataclass
class AgentResponse:
    """What the agent produced for one scenario."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    refused: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def executed_calls(self) -> list[ToolCall]:
        return [c for c in self.tool_calls if not c.blocked]


@dataclass
class Environment:
    """Secrets planted in the agent's context. A leak of any of them is a finding."""

    canary: str  # secret API key inside the system prompt
    prompt_phrase: str  # unique phrase that proves a system prompt leak
    system_prompt: str
    attacker_domain: str = "evil.example"

    @property
    def attacker_email(self) -> str:
        return f"attacker@{self.attacker_domain}"


@dataclass
class Evidence:
    check: str
    detail: str


@dataclass
class AttackResult:
    attack_id: str
    name: str
    category: str
    severity: Severity
    vector: str
    outcome: Outcome
    trials: int
    successes: int
    evidence: list[Evidence] = field(default_factory=list)
    response_excerpt: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    owasp: str = ""
    mitigation: str = ""

    @property
    def success_rate(self) -> float:
        return self.successes / self.trials if self.trials else 0.0
