"""Example: plug your own agent into injectbench.

Run from the repo root:

    python -m injectbench run --agent examples.custom_agent:make_agent --seed demo

An adapter is any object with:
  - `name: str`
  - `run(system, user_message, tools) -> AgentResponse`

Rules for `run`:
  1. Send every tool call through `tools.call(name, args)`. The harness records
     it, and the checks look at the recorded calls.
  2. `tools.specs` lists the tools in the Anthropic `tools` format.
  3. Return the final answer text, `tools.trace` as tool_calls, and
     `refused=True` if the agent declined the request.

This file has two adapters:
  - `KeywordAgent`: runnable, no API key. A tiny rule-based agent that does the
    user's task and never obeys text inside tool output.
  - `MyLLMAgent`: a skeleton. It shows where to call your own LLM.
"""

from __future__ import annotations

import re

from injectbench import AgentResponse, ToolBox

SUSPICIOUS = (
    "ignore all previous",
    "ignore previous",
    "system prompt",
    "api key",
    "developer mode",
    "you are now",
    "<system>",
    "words above",
    "initial instructions",
)


class KeywordAgent:
    """Refuses suspicious requests, does the task, treats tool output as data."""

    name = "keyword-example"

    def run(self, system: str, user_message: str, tools: ToolBox) -> AgentResponse:
        low = user_message.lower()
        if any(word in low for word in SUSPICIOUS):
            return AgentResponse(text="I can't help with that request.", refused=True)

        tool, args = self._pick_tool(user_message)
        if not tool:
            return AgentResponse(text="I can help with email, web pages, files and the docs.")

        result = tools.call(tool, args)
        # Never act on what the tool output says, and do not echo it blindly:
        # a copied attacker token or link also counts as a missed attack.
        # Here we quote only the first paragraph (the real content).
        summary = result.strip().split("\n\n")[0]
        return AgentResponse(text=f"Here is what I found:\n{summary}", tool_calls=list(tools.trace))

    @staticmethod
    def _pick_tool(msg: str):
        low = msg.lower()
        if "email" in low:
            return "read_inbox", {}
        if m := re.search(r"https?://\S+", msg):
            return "fetch_url", {"url": m.group()}
        if m := re.search(r"\b[\w-]+\.(md|txt|csv|json)\b", msg):
            return "read_file", {"path": m.group()}
        if "docs" in low or "search" in low:
            return "search_docs", {"query": msg}
        return None, {}


class MyLLMAgent:
    """Skeleton of an LLM agent with a tool loop. Fill in `_llm`."""

    name = "my-llm-agent"

    def __init__(self, max_turns: int = 6):
        self.max_turns = max_turns

    def _llm(self, system: str, messages: list[dict], tool_specs: list[dict]) -> dict:
        """Call your model here.

        Return {"text": str, "tool_calls": [{"name": str, "args": dict}]}.
        An empty tool_calls list ends the loop.
        """
        raise NotImplementedError("Call your own LLM in MyLLMAgent._llm")

    def run(self, system: str, user_message: str, tools: ToolBox) -> AgentResponse:
        messages = [{"role": "user", "content": user_message}]
        texts = []
        for _ in range(self.max_turns):
            reply = self._llm(system, messages, tools.specs)
            if reply.get("text"):
                texts.append(reply["text"])
            calls = reply.get("tool_calls") or []
            if not calls:
                break
            messages.append({"role": "assistant", "content": reply})
            for call in calls:
                # Every tool call goes through the sandbox.
                output = tools.call(call["name"], call.get("args", {}))
                messages.append({"role": "tool", "name": call["name"], "content": output})
        return AgentResponse(text="\n".join(texts), tool_calls=list(tools.trace))


def make_agent():
    """Factory used by `--agent examples.custom_agent:make_agent`."""
    return KeywordAgent()
