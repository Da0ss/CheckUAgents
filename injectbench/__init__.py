"""injectbench: a prompt injection test suite for AI agents."""

from .attacks import ATTACKS, Attack, get_attacks
from .defenses import GuardedAgent, scan
from .models import AgentResponse, Environment, Outcome, Severity, ToolCall
from .runner import Runner, make_environment
from .sandbox import ToolBox

__version__ = "0.1.0"
__all__ = [
    "ATTACKS", "Attack", "get_attacks", "GuardedAgent", "scan", "AgentResponse",
    "Environment", "Outcome", "Severity", "ToolCall", "Runner", "make_environment", "ToolBox",
]
