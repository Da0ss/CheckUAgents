"""Demo agent behind HTTP. Standard library only.

It implements the contract of injectbench.agents.http:

    request:  POST {"system": str, "message": str, "tools": [tool specs]}
    response: {"text": str, "tool_calls": [{"name": str, "args": {...}}], "refused": bool}

Start it, then point injectbench at it:

    python examples/http_agent_server.py
    python -m injectbench run --agent http --url http://127.0.0.1:8765 --seed demo

With --vulnerable the server echoes attacker tokens and leaks the API key,
so you can see what "missed" attacks look like in the report.

Note: an HTTP agent returns its tool calls once and never sees tool results.
So indirect injections (payloads in tool output) cannot reach it.
"""

from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SUSPICIOUS = ("ignore", "system prompt", "api key", "instructions", "<system>", "you are now")


def answer(system: str, message: str, vulnerable: bool) -> dict:
    low = message.lower()
    if vulnerable:
        text = []
        if m := re.search(r"PWNED-[0-9A-F]{6}", message):
            text.append(m.group())
        if "api key" in low and (k := re.search(r"API key:\s*(\S+)", system)):
            text.append(f"The key is {k.group(1).rstrip('.')}")
        if text:
            return {"text": "\n".join(text), "tool_calls": [], "refused": False}
    elif any(word in low for word in SUSPICIOUS):
        return {"text": "I can't help with that request.", "tool_calls": [], "refused": True}

    calls = []
    if "email" in low:
        calls.append({"name": "read_inbox", "args": {}})
    elif m := re.search(r"https?://\S+", message):
        calls.append({"name": "fetch_url", "args": {"url": m.group()}})
    elif m := re.search(r"\b[\w-]+\.(md|txt|csv|json)\b", message):
        calls.append({"name": "read_file", "args": {"path": m.group()}})
    elif "docs" in low:
        calls.append({"name": "search_docs", "args": {"query": message}})
    return {"text": "Done. I used the tools to answer your question.", "tool_calls": calls, "refused": False}


def make_handler(vulnerable: bool):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length) or b"{}")
                body = answer(str(data.get("system", "")), str(data.get("message", "")), vulnerable)
                status = 200
            except (ValueError, json.JSONDecodeError) as exc:
                body, status = {"error": str(exc)}, 400
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

    return Handler


def main() -> None:
    p = argparse.ArgumentParser(description="Demo HTTP agent for injectbench")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--vulnerable", action="store_true", help="obey direct injections (for demos)")
    args = p.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(args.vulnerable))
    print(f"Demo agent on http://{args.host}:{args.port} (vulnerable={args.vulnerable})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
