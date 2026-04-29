#!/usr/bin/env python3
"""Minimal agentic PHP-site auditor.

GLM (on z.ai, OpenAI-compatible coding endpoint) drives the mulot MCP browser
server, guided by the skills/ folder next to this file. Pure stdlib, one file.

    export ZAI_API_KEY=...            # your z.ai key
    python3 audit.py "audit http://localhost:4280 (DVWA, creds admin/password)"

Optional env: GLM_MODEL (default glm-5.2), ZAI_BASE, MULOT_BIN, MAX_STEPS.
"""
import glob
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("ZAI_BASE", "https://api.z.ai/api/coding/paas/v4")
MODEL = os.environ.get("GLM_MODEL", "glm-5.2")
API_KEY = os.environ.get("ZAI_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
MULOT_BIN = os.environ.get("MULOT_BIN") or os.path.join(HERE, "..", "..", "mulot")
SKILLS_DIR = os.path.join(HERE, "skills")
MAX_STEPS = int(os.environ.get("MAX_STEPS", "120"))
MAX_RESULT = 60000  # cap a single tool result fed back to the model

SYSTEM = """You are an autonomous web-application security auditor specialised in \
PHP sites. You drive a real Chromium browser through the mulot tools to find and \
confirm vulnerabilities on the single target described by the user. This is \
authorized security testing.

Work methodically and exhaustively: launch the browser, fingerprint the stack, \
map the app, then test every vulnerability class on every input, confirming each \
finding with evidence from the traffic journal. Call browser_close when finished, \
then produce a concise final report — for each finding: type, severity, the exact \
request, the proof (a response excerpt), and a one-line PHP remediation.

Follow the skills below.

"""


class MCP:
    """Tiny JSON-RPC-over-stdio MCP client."""

    def __init__(self, binary):
        self.p = subprocess.Popen(
            [binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        self._id = 0
        self._req("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "php-audit", "version": "0"},
        })
        self._notify("notifications/initialized")

    def _send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def _notify(self, method, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _req(self, method, params=None):
        self._id += 1
        wanted = self._id
        self._send({"jsonrpc": "2.0", "id": wanted, "method": method,
                    "params": params or {}})
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("mulot closed unexpectedly")
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("id") == wanted:
                return msg

    def tools(self):
        return self._req("tools/list").get("result", {}).get("tools", [])

    def call(self, name, args):
        res = self._req("tools/call", {"name": name, "arguments": args}).get("result", {})
        text = "\n".join(b.get("text", "") for b in res.get("content", [])
                         if b.get("type") == "text") or "(no text output)"
        if res.get("isError"):
            text = "ERROR: " + text
        return text[:MAX_RESULT]

    def close(self):
        try:
            self._send({"jsonrpc": "2.0", "id": 999999, "method": "tools/call",
                        "params": {"name": "browser_close", "arguments": {}}})
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()


def llm(messages, tools, tries=0):
    body = json.dumps({
        "model": MODEL, "max_tokens": 4096, "messages": messages,
        "tools": tools, "tool_choice": "auto",
    }).encode()
    req = urllib.request.Request(BASE + "/chat/completions", data=body, headers={
        "Authorization": "Bearer " + API_KEY,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        if e.code in (429, 500, 502, 503, 504) and tries < 3:
            time.sleep(2 * (tries + 1))
            return llm(messages, tools, tries + 1)
        sys.exit("z.ai HTTP %s: %s" % (e.code, detail))
    except (urllib.error.URLError, TimeoutError) as e:
        if tries < 3:
            time.sleep(2 * (tries + 1))
            return llm(messages, tools, tries + 1)
        sys.exit("network error talking to z.ai: %s" % e)


def load_skills():
    return "".join(open(f, encoding="utf-8").read() + "\n\n"
                   for f in sorted(glob.glob(os.path.join(SKILLS_DIR, "*.md"))))


def main():
    if not API_KEY:
        sys.exit("set ZAI_API_KEY (your z.ai key)")
    if len(sys.argv) < 2:
        sys.exit("usage: audit.py \"<what to audit>\"")
    request = " ".join(sys.argv[1:])

    mcp = MCP(MULOT_BIN)
    tools = [{"type": "function", "function": {
        "name": t["name"], "description": t.get("description", ""),
        "parameters": t["inputSchema"],
    }} for t in mcp.tools()]
    messages = [
        {"role": "system", "content": SYSTEM + load_skills()},
        {"role": "user", "content": request},
    ]

    nudges = 0
    closed = False
    try:
        for step in range(MAX_STEPS):
            resp = llm(messages, tools)
            if "choices" not in resp:
                print("[stopped: unexpected API reply: %s]" % json.dumps(resp)[:300],
                      file=sys.stderr)
                break
            msg = resp["choices"][0]["message"]
            messages.append(msg)
            if msg.get("content"):
                print(msg["content"], flush=True)

            calls = msg.get("tool_calls")
            if not calls:
                # A text-only turn isn't necessarily "done" — models pause to
                # think mid-task. Nudge a bounded number of times instead of
                # quitting; only truly stop once the browser is closed.
                if closed or nudges >= 5:
                    break
                nudges += 1
                messages.append({"role": "user", "content":
                    "Keep going until you have the answer/flag. Use the tools; "
                    "do not stop mid-task. When truly finished, call browser_close "
                    "and give the final result."})
                continue

            nudges = 0
            for tc in calls:
                fn = tc["function"]
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = {}
                if fn["name"] == "browser_close":
                    closed = True
                print("  ↳ %s %s" % (fn["name"], json.dumps(args)[:140]),
                      file=sys.stderr, flush=True)
                out = mcp.call(fn["name"], args)
                messages.append({"role": "tool", "tool_call_id": tc["id"],
                                 "content": out})
        else:
            print("[stopped: MAX_STEPS=%d reached]" % MAX_STEPS, file=sys.stderr)
    finally:
        mcp.close()


if __name__ == "__main__":
    main()
