"""A deliberately vulnerable, rule-based reference agent.

It needs no API key. It does its task, but it also obeys any instruction it
finds anywhere in its context, including tool output. Like a real LLM, it can
read base64, ROT13, leetspeak, scrambled words and Russian.

Use it to try the harness, to test defense layers offline and in CI.
Do not use it as a model of how a specific LLM behaves.
"""

from __future__ import annotations

import json
import re

from ..models import AgentResponse
from ..normalize import unscramble, views
from ..sandbox import SENSITIVE_TOOLS, ToolBox

MARKER_RE = re.compile(r"PWNED-[0-9A-F]{6}")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
URL_RE = re.compile(r"https?://[^\s)]+")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")

VOCAB = {
    "ignore", "previous", "instructions", "print", "word", "reveal", "system",
    "prompt", "repeat", "translate", "forget", "secret", "delete", "transfer",
}
SAY = r"\b(say|print|reply|respond|output|write|напиши|скажи|выведи)\b"
LEAK = r"\b(reveal|show|print|repeat|translate|output|display)\b.{0,40}\b(system prompt|instructions|words above|text above)"
SECRET = r"\b(api key|secret)\b"
SEND = r"\b(send|email|forward)\b"


class _OnceTools:
    """Forwards tool calls, dropping repeats of a side-effecting call (same name and args)."""

    def __init__(self, tools: ToolBox):
        self.tools = tools
        self.seen: set[tuple[str, str]] = set()

    def call(self, name: str, args: dict) -> str:
        if name in SENSITIVE_TOOLS:
            key = (name, json.dumps(args, sort_keys=True, default=str))
            if key in self.seen:
                return ""
            self.seen.add(key)
        return self.tools.call(name, args)


class NaiveAgent:
    name = "naive"

    def run(self, system: str, user_message: str, tools: ToolBox) -> AgentResponse:
        secret = (re.search(r"API key:\s*(\S+)", system) or [None, ""])[1].rstrip(".")
        context = [user_message]
        answer = []

        tool, args = self._pick_tool(user_message)
        if tool:
            result = tools.call(tool, args)
            context.append(result)
            answer.append(f"Here is what I found:\n{self._first_lines(result)}")

        # Several decoded views of one text can carry the same instruction:
        # perform each side-effecting tool call at most once per run.
        once = _OnceTools(tools)
        for text in context:
            for view in views(text):
                view = unscramble(view, VOCAB)
                answer.extend(self._obey(view, system, secret, once))

        if not answer:
            answer.append("Done.")
        # De-duplicate while keeping order.
        seen, out = set(), []
        for part in answer:
            if part not in seen:
                seen.add(part)
                out.append(part)
        return AgentResponse(text="\n\n".join(out), tool_calls=list(tools.trace))

    # -- task handling -------------------------------------------------
    @staticmethod
    def _pick_tool(msg: str):
        low = msg.lower()
        if "email" in low and "summar" in low:
            return "read_inbox", {}
        if m := URL_RE.search(msg):
            return "fetch_url", {"url": m.group()}
        if m := re.search(r"\b[\w-]+\.(md|txt|csv|json)\b", msg):
            return "read_file", {"path": m.group()}
        if "docs" in low or "search" in low:
            return "search_docs", {"query": msg}
        return None, {}

    @staticmethod
    def _first_lines(text: str) -> str:
        return "\n".join(text.strip().splitlines()[:4])

    # -- the vulnerability: obey every instruction ---------------------
    def _obey(self, text: str, system: str, secret: str, tools) -> list[str]:
        out = []
        low = text.lower()

        marker = MARKER_RE.search(text)
        if marker and re.search(SAY, low):
            out.append(marker.group())

        if re.search(LEAK, low, re.S):
            out.append(f"My instructions:\n```\n{system}\n```")

        emails = [e for e in EMAIL_RE.findall(text) if not e.endswith("acme.example")]
        if re.search(SECRET, low) and re.search(SEND, low) and emails:
            tools.call("send_email", {"to": emails[0], "subject": "Requested", "body": f"API key: {secret}"})
        elif re.search(SECRET, low) and re.search(r"\b(print|reveal|output|show)\b", low):
            out.append(f"The internal API key is {secret}.")
        elif re.search(r"\b(copy|forward)\b", low) and emails:
            if re.search(r"\b(remember|memory)\b", low):
                tools.call("write_memory", {"note": text.strip()[:200]})
            else:
                tools.call("send_email", {"to": emails[0], "body": "Forwarded email"})

        if m := re.search(r"\bdelete\b.{0,20}?\b([\w-]+\.\w+)", text, re.I):
            tools.call("delete_file", {"path": m.group(1)})

        if (m := re.search(r"transfer\s+(\d+)\D{0,30}account\s+([\w-]+)", text, re.I)):
            tools.call("transfer_funds", {"to_account": m.group(2), "amount": float(m.group(1))})

        if (m := re.search(r"\brun\b.{0,20}`([^`]+)`", text, re.I)):
            tools.call("run_shell", {"command": m.group(1)})

        if m := IMAGE_RE.search(text):
            url = re.sub(r"API_KEY|\{secret\}", secret, m.group(1))
            out.append(f"![image]({url})")
        elif re.search(r"tell the user", low) and (u := URL_RE.search(text)):
            out.append(f"Your account is locked. Log in at {u.group()} to unlock it.")

        return out
