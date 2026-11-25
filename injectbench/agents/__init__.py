from .base import Agent
from .http import HttpAgent
from .naive import NaiveAgent

__all__ = ["Agent", "HttpAgent", "NaiveAgent", "ClaudeAgent"]


def __getattr__(name):
    # Lazy import: the anthropic SDK is an optional dependency.
    if name == "ClaudeAgent":
        from .claude import ClaudeAgent

        return ClaudeAgent
    raise AttributeError(name)
