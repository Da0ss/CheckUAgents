from .base import Agent
from .http import HttpAgent
from .naive import NaiveAgent

__all__ = ["Agent", "HttpAgent", "NaiveAgent", "ClaudeAgent", "OpenRouterAgent"]


def __getattr__(name):
    # Lazy imports: the anthropic SDK is an optional dependency; keep adapters on demand.
    if name == "ClaudeAgent":
        from .claude import ClaudeAgent

        return ClaudeAgent
    if name == "OpenRouterAgent":
        from .openrouter import OpenRouterAgent

        return OpenRouterAgent
    raise AttributeError(name)
