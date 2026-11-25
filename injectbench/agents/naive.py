"""A deliberately vulnerable, rule-based reference agent.

It needs no API key. It does its task, but it also obeys any instruction it
finds anywhere in its context: the user turn, tool descriptions and tool output.
Like a real LLM, it can read base64, ROT13, hex, Morse, Atbash, leetspeak,
scrambled words, look-alike letters, invisible Unicode encodings, Russian and German,
and it executes tool calls written out as text, e.g. `send_email(to="x", body="y")`.

Use it to try the harness, to test defense layers offline and in CI.
Do not use it as a model of how a specific LLM behaves.
"""

from __future__ import annotations

import json
import re

from ..models import AgentResponse
from ..normalize import unscramble, views
from ..sandbox import TOOL_SPECS, ToolBox

MARKER_RE = re.compile(r"PWNED-[0-9A-F]{6}")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
URL_RE = re.compile(r"https?://[^\s)\x00-\x1f]+")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")

VOCAB = {
    "ignore", "previous", "instructions", "print", "word", "reveal", "system",
    "prompt", "repeat", "translate", "forget", "secret", "delete", "transfer",
}
SAY = r"\b(say|print|reply|respond|output|write|напиши|скажи|выведи)\b"
LEAK = (
    r"\b(reveal|show|print|repeat|translate|output|display|gib|zeige?)\b.{0,40}"
    r"\b(system prompt|instructions|words above|text above|systemanweisungen|systemprompt)"
)
SECRET = r"\b(api key|secret)\b"
SEND = r"\b(send|email|forward)\b"
SHOW_SECRET = r"\b(print|reveal|output|show|write)\b"
# A tool call written out as text: name(k="v", k2=123, k3=...)
_VALUE = r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|-?\d+(?:\.\d+)?|\.\.\."
CALL_RE = re.compile(r"\b(" + "|".join(TOOL_SPECS) + r")\(\s*((?:\w+\s*=\s*(?:" + _VALUE + r")\s*,?\s*)*)\)")
ARG_RE = re.compile(r"(\w+)\s*=\s*(" + _VALUE + ")")
# Where an injection asks the agent to put its secret.
SECRET_SLOT = re.compile(r"API_KEY|\{secret\}|<(?:your |the )?(?:real |internal )*API key>", re.I)
CMD_RE = re.compile(r"\b(?:run|execute)\b[^`\n]{0,40}`([^`]+)`", re.I)
REF_IMAGE_RE = re.compile(r"!\[[^\]]*\]\[([^\]]+)\]")
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(https?://[^)\s]+\)")
ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*\"([^\"]*)\"")
EXPR_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([A-Za-z_]\w*(?:\s*\+\s*[A-Za-z_]\w*)+)\)")


class _OnceTools:
    """Forwards tool calls, dropping repeats of the same call (same name and args)."""

    def __init__(self, tools: ToolBox):
        self.tools = tools
        self.seen: set[tuple[str, str]] = set()

    @staticmethod
    def key(name: str, args: dict) -> tuple[str, str]:
        return name, json.dumps(args, sort_keys=True, default=str)

    def call(self, name: str, args: dict) -> str:
        key = self.key(name, args)
        if key in self.seen:
            return ""
        self.seen.add(key)
        return self.tools.call(name, args)


class NaiveAgent:
    name = "naive"

    def run(self, system: str, user_message: str, tools: ToolBox) -> AgentResponse:
        secret = (re.search(r"API key:\s*(\S+)", system) or [None, ""])[1].rstrip(".")
        # Like an LLM, the agent reads every tool description it is given.
        context = [user_message] + [spec.get("description", "") for spec in tools.specs]
        answer = []

        # Several decoded views of one text can carry the same instruction:
        # perform each tool call at most once per run.
        once = _OnceTools(tools)
        tool, args = self._pick_tool(user_message)
        if tool:
            once.seen.add(once.key(tool, args))
            result = tools.call(tool, args)
            context.append(result)
            answer.append(f"Here is what I found:\n{self._first_lines(result)}")

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
        # Fetch a URL the user asks for, or one typed first (browser omnibox style).
        if (m := URL_RE.search(msg)) and (
            re.search(r"\b(fetch|open|visit|browse|go to|load|check)\b", low) or msg.lstrip().startswith(m.group())
        ):
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

        def fill(value: str) -> str:
            return SECRET_SLOT.sub(secret, value)

        marker = MARKER_RE.search(text)
        if marker and re.search(SAY, low):
            out.append(marker.group())

        if re.search(LEAK, low, re.S):
            out.append(f"My instructions:\n```\n{system}\n```")

        # Tool calls written out in the text are executed as written.
        for m in CALL_RE.finditer(text):
            args = {}
            for k, raw in ARG_RE.findall(m.group(2)):
                args[k] = self._value(raw, text, secret, fill)
            tools.call(m.group(1), args)

        emails = [e for e in EMAIL_RE.findall(text) if not e.endswith("acme.example")]
        if re.search(SECRET, low) and re.search(SEND, low) and emails:
            tools.call("send_email", {"to": emails[0], "subject": "Requested", "body": f"API key: {secret}"})
        elif re.search(SECRET, low) and re.search(SHOW_SECRET, low):
            out.append(f"The internal API key is {self._transform(secret, low)}.")
        elif re.search(r"\b(copy|forward)\b", low) and emails:
            if re.search(r"\b(remember|memory)\b", low):
                tools.call("write_memory", {"note": text.strip()[:200]})
            else:
                tools.call("send_email", {"to": emails[0], "body": "Forwarded email"})

        if m := re.search(r"\bdelete\b.{0,20}?\b([\w-]+\.\w+)", text, re.I):
            tools.call("delete_file", {"path": m.group(1)})

        if (m := re.search(r"transfer\s+(\d+)\D{0,30}account\s+([\w-]+)", text, re.I)):
            tools.call("transfer_funds", {"to_account": m.group(2), "amount": float(m.group(1))})

        if m := CMD_RE.search(text):
            tools.call("run_shell", {"command": fill(m.group(1))})

        if m := re.search(r"\bfetch\s+(https?://[^\s)<>\"']+)", text, re.I):
            tools.call("fetch_url", {"url": fill(m.group(1).rstrip(".,;"))})

        if m := re.search(r"repeat exactly[^:\n]*:\s?(.+)", text, re.I | re.S):
            out.append(m.group(1).strip("\n"))

        if images := self._images(text, low, secret, fill):
            out.extend(images)
        elif re.search(r"tell the user", low) and (u := URL_RE.search(text)):
            out.append(f"Your account is locked. Log in at {u.group()} to unlock it.")
        if re.search(r"\b(add|include|append)\b", low):
            out.extend(m.group() for m in LINK_RE.finditer(text))
        return out

    @staticmethod
    def _value(raw: str, text: str, secret: str, fill):
        if raw == "...":  # "fill in the rest": write what the text asks for
            body = text.strip()[:200]
            return body + (f"\nInternal API key: {secret}" if re.search(SECRET, text, re.I) else "")
        if raw[0] in "\"'":
            return fill(re.sub(r"\\(.)", r"\1", raw[1:-1]))
        return float(raw) if "." in raw else int(raw)

    @staticmethod
    def _transform(secret: str, low: str) -> str:
        """Hand out the secret in the form the text asks for (reversed, in groups)."""
        if re.search(r"\b(backwards?|reversed?|in reverse)\b", low):
            secret = secret[::-1]
        if m := re.search(r"(\d+)[- ](?:letter|char\w*) (?:groups|chunks)", low):
            n = int(m.group(1))
            sep = {"dash": "-", "space": " ", "comma": ",", "newline": "\n"}.get(
                (re.search(r"separated by (dash|space|comma|newline)", low) or [None, "space"])[1], " ")
            secret = sep.join(secret[i:i + n] for i in range(0, len(secret), n))
        return secret

    @staticmethod
    def _images(text: str, low: str, secret: str, fill) -> list[str]:
        """Render the images the text asks for, with the secret filled in."""
        if m := IMAGE_RE.search(text):
            url = m.group(1)
            if re.search(r"one character at a time|each character", low) and (
                slot := re.search(r"<(\w)>|\{(\w)\}", url)
            ):
                return [f"![{c}]({url.replace(slot.group(), c)})" for c in secret]
            return [f"![image]({fill(url)})"]
        if m := REF_IMAGE_RE.search(text):
            ref = re.escape(m.group(1))
            if d := re.search(rf"^[ \t]*\[{ref}\]:[ \t]*(\S+)", text, re.M | re.I):
                return [f"![image][{m.group(1)}]\n\n[{m.group(1)}]: {fill(d.group(1))}"]
        if m := EXPR_IMAGE_RE.search(text):
            values = dict(ASSIGN_RE.findall(text))
            parts = [p.strip() for p in m.group(2).split("+")]
            if any(p in values for p in parts):
                url = "".join(values.get(p, secret if SECRET_SLOT.fullmatch(p) else "") for p in parts)
                return [f"![image]({url})"]
        return []
