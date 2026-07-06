#!/usr/bin/env python3
"""Minimal agentic web-app security auditor (multi-stack, multi-provider).

Drives the mulot MCP browser server through any OpenAI-compatible chat-completions
endpoint with tool calling. Seeds the shared workflow at launch from mulot's own
`load_skill` tool (no args), fingerprints the target, then lets the model call
mulot's real `load_skill` tool to pull tailored per-stack playbooks — no synthetic
router. Pass --ingest <file.md> (repeatable) to prime the context with a prior report.

Providers (OpenAI-compatible chat/completions + tool calling):
  openrouter  https://openrouter.ai/api/v1          key: OPENROUTER_API_KEY
  llamacpp    http://localhost:8080/v1              key: LLAMA_API_KEY (often unused)
  zai         https://api.z.ai/api/coding/paas/v4   key: ZAI_API_KEY

    export OPENROUTER_API_KEY=...
    python3 agent.py --provider openrouter --model anthropic/claude-opus-4.1 \
        "audit http://localhost:8000"

    # local llama.cpp (llama-server --jinja -m model.gguf --port 8080):
    python3 agent.py --provider llamacpp --model local "audit http://localhost:8000"

Env defaults: LLM_PROVIDER, LLM_MODEL, LLM_BASE, LLM_API_KEY, MULOT_BIN,
MULOT_JOURNAL_DB, MAX_STEPS.
"""
import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_RESULT = 60000  # cap a single (untrusted) tool result fed back to the model

PROVIDERS = {
    "openrouter": {"base": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY",
                   "default_model": None},
    "llamacpp":   {"base": "http://192.168.0.11:8080/v1", "key_env": "LLAMA_API_KEY",
                   "default_model": "qwen3.6-mtp"},
    "zai":        {"base": "https://api.z.ai/api/coding/paas/v4", "key_env": "ZAI_API_KEY",
                   "default_model": "glm-5.2"},
}

SYSTEM = """You are an autonomous web-application security auditor. You drive a \
real Chromium browser through the mulot tools to find and confirm vulnerabilities \
on the single target described by the user. This is authorized security testing.

You begin with the shared workflow and the full tool list below, but WITHOUT any \
stack-specific playbooks. Work methodically: launch the browser, FINGERPRINT the \
target to identify its technology stack(s), then call the `load_skill` tool with \
the detected stack name(s) to load the tailored testing skills (call it again if \
you later detect another). Then map the app, run a passive pass, authenticate, and \
test every \
vulnerability class on every input, confirming each finding with evidence from the \
traffic journal. Call browser_close when finished, then produce a concise final \
report — for each finding: type, severity, the exact request, the proof (a \
response excerpt), and a one-line remediation in the target's language.

Follow the shared workflow below.

"""


class MCP:
    """Tiny JSON-RPC-over-stdio MCP client with a per-call timeout.

    A background thread drains mulot's stdout into a queue so a single hung tool
    call (e.g. browser_upload_file waiting on a file chooser, or browser_type
    triggering a blocking JS dialog) can't deadlock the whole run: the call times
    out and returns an error the model can recover from. Two timeouts in a row
    mean mulot is wedged, so we abort the session instead of hanging forever.
    """

    def __init__(self, binary, call_timeout=180):
        self.call_timeout = call_timeout
        self.p = subprocess.Popen(
            [binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        self._id = 0
        self._timeouts = 0          # consecutive tool-call timeouts
        self._q = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._req("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "mulot-agent", "version": "0"},
        }, timeout=30)
        self._notify("notifications/initialized")

    def _read_loop(self):
        """Own mulot's stdout: parse every line into the queue until it closes."""
        for line in self.p.stdout:
            try:
                self._q.put(json.loads(line))
            except ValueError:
                continue
        self._q.put(None)           # sentinel: stream closed (mulot exited)

    def _send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def _notify(self, method, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _req(self, method, params=None, timeout=None):
        self._id += 1
        wanted = self._id
        self._send({"jsonrpc": "2.0", "id": wanted, "method": method,
                    "params": params or {}})
        limit = self.call_timeout if timeout is None else timeout
        deadline = time.time() + limit
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("no response to %s within %ds" % (method, limit))
            try:
                msg = self._q.get(timeout=remaining)
            except queue.Empty:
                continue            # loop re-checks the deadline, then raises
            if msg is None:
                raise RuntimeError("mulot closed unexpectedly")
            if msg.get("id") == wanted:
                return msg
            # else: a notification or a late reply to a timed-out call — drop it

    def tools(self):
        return self._req("tools/list").get("result", {}).get("tools", [])

    def call(self, name, args):
        try:
            msg = self._req("tools/call", {"name": name, "arguments": args})
        except TimeoutError:
            self._timeouts += 1
            if self._timeouts >= 2:
                raise RuntimeError(
                    "mulot unresponsive: %d tool calls in a row timed out "
                    "(>=%ds each); the browser likely hung on a call such as "
                    "'%s'. Aborting the session." % (self._timeouts, self.call_timeout, name))
            return ("ERROR: tool '%s' timed out after %ds with no response from "
                    "mulot — it likely hung (e.g. a file chooser or a blocking "
                    "JS dialog). Do NOT repeat this call; try a different "
                    "approach (another selector, set a dialog mode, or skip it)."
                    % (name, self.call_timeout))
        self._timeouts = 0
        res = msg.get("result", {})
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


def llm(cfg, messages, tools, tries=0):
    payload = {"model": cfg["model"], "max_tokens": cfg["max_tokens"],
               "messages": messages, "tools": tools, "tool_choice": "auto"}
    headers = {"Authorization": "Bearer " + cfg["key"], "Content-Type": "application/json"}
    headers.update(cfg.get("headers") or {})
    req = urllib.request.Request(cfg["base"].rstrip("/") + "/chat/completions",
                                 data=json.dumps(payload).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=cfg["timeout"]) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        if e.code in (408, 409, 429, 500, 502, 503, 504) and tries < 4:
            time.sleep(2 * (tries + 1))
            return llm(cfg, messages, tools, tries + 1)
        sys.exit("LLM HTTP %s: %s" % (e.code, detail[:500]))
    except (urllib.error.URLError, TimeoutError) as e:
        if tries < 4:
            time.sleep(2 * (tries + 1))
            return llm(cfg, messages, tools, tries + 1)
        sys.exit("network error talking to the LLM: %s" % e)


def clean_assistant(msg):
    """Echo back only the fields every provider accepts (drop reasoning/extras)."""
    out = {"role": "assistant", "content": msg.get("content") or ""}
    if msg.get("tool_calls"):
        out["tool_calls"] = msg["tool_calls"]
    return out


def tool_args(fn):
    """Tool-call arguments arrive as a JSON string (OpenAI) or an object (some)."""
    raw = fn.get("arguments")
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}


def parse_args(argv):
    p = argparse.ArgumentParser(description="Agentic web-app auditor over mulot (MCP).")
    p.add_argument("request", nargs="+", help='what to audit, e.g. "audit http://host"')
    p.add_argument("--provider", default=None, choices=list(PROVIDERS),
                   help="LLM provider (default: auto-detected from whichever API key is set)")
    p.add_argument("--model", default=os.environ.get("LLM_MODEL"))
    p.add_argument("--base", default=os.environ.get("LLM_BASE"),
                   help="override the chat-completions base URL")
    p.add_argument("--key", default=os.environ.get("LLM_API_KEY"),
                   help="override the API key")
    p.add_argument("--max-steps", type=int, default=int(os.environ.get("MAX_STEPS", "120")))
    p.add_argument("--max-tokens", type=int, default=4096)
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--call-timeout", type=int,
                   default=int(os.environ.get("CALL_TIMEOUT", "180")),
                   help="per-tool-call timeout (s): a hung browser op aborts the "
                        "session instead of hanging the agent forever")
    p.add_argument("--mulot", default=os.environ.get("MULOT_BIN") or os.path.join(HERE, "mulot"))
    p.add_argument("--journal", default=os.environ.get("MULOT_JOURNAL_DB"),
                   help="traffic journal path (isolate parallel runs)")
    p.add_argument("--ingest", action="append", default=[], metavar="FILE",
                   help="inject a prior report (markdown) into the context at "
                        "launch, so this run builds on it; repeatable")
    p.add_argument("--out", help="write a JSON metrics summary to this path")
    return p.parse_args(argv)


def auto_provider():
    """Default provider = the first one whose API key is present in the env."""
    for p in ("openrouter", "zai"):
        if os.environ.get(PROVIDERS[p]["key_env"]):
            return p
    return None


def resolve_cfg(args):
    # 'zai'/'openrouter'/... are PROVIDERS, not models — catch the common slip
    # (e.g. `--model zai` when you meant `--provider zai`).
    if args.model and args.model in PROVIDERS:
        sys.exit("'%s' is a PROVIDER, not a model — use: --provider %s" % (args.model, args.model))

    provider = args.provider or os.environ.get("LLM_PROVIDER") or auto_provider() or "openrouter"
    preset = PROVIDERS[provider]
    base = args.base or preset["base"]
    model = args.model or preset["default_model"]
    if not model:
        sys.exit("provider '%s' needs an explicit model. Examples:\n"
                 "  --provider zai                            # glm-5.2\n"
                 "  --provider openrouter --model z-ai/glm-4.6\n"
                 "  --provider llamacpp  --model local        # local llama-server"
                 % provider)
    key = args.key or os.environ.get(preset["key_env"])
    if not key:
        if provider == "llamacpp":
            key = "no-key"  # llama-server ignores it
        else:
            sys.exit("set %s (or pass --key) for --provider %s" % (preset["key_env"], provider))
    headers = {}
    if provider == "openrouter":
        headers = {"HTTP-Referer": "https://github.com/io-tl/mulot", "X-Title": "mulot-agent"}
    return {"provider": provider, "base": base, "model": model, "key": key,
            "headers": headers, "max_tokens": args.max_tokens, "timeout": args.timeout}


def main():
    args = parse_args(sys.argv[1:])
    request = " ".join(args.request)
    cfg = resolve_cfg(args)

    # Echo the task prompt at the very start of the session so every transcript /
    # benchmark log records exactly what was asked (and with which model).
    print("=== session start: %s/%s ===" % (cfg["provider"], cfg["model"]),
          file=sys.stderr, flush=True)
    print("PROMPT: %s" % request, file=sys.stderr, flush=True)

    metrics = {"provider": cfg["provider"], "model": cfg["model"], "request": request,
               "steps": 0, "tool_calls": 0, "tokens": 0, "stacks": [],
               "closed": False, "report": "", "error": None, "wall_s": 0.0,
               # Per-model tool-calling diagnostics: which tools the model reached
               # for (usage histogram), which ones returned an error (with a short
               # sample of the message), how it delivered arguments (a JSON object
               # vs a stringified object — a known GLM/quirk axis), and how many
               # times it fell into a repeat-loop. This is the data that says WHERE
               # a given model struggles with mulot, so optimisation is measured,
               # not guessed.
               "tool_usage": {}, "tool_errors": {}, "error_samples": [],
               "arg_shape": {"dict": 0, "string": 0}, "loops": 0}
    t0 = time.time()

    mcp = MCP(args.mulot, call_timeout=args.call_timeout)
    # No synthetic router: the model calls mulot's real load_skill/list_skills tools
    # to pull stack playbooks itself. We only SEED the shared workflow (load_skill
    # with no args) into the system prompt, so the model knows its capabilities up
    # front — before it has fingerprinted the target's stack.
    workflow = mcp.call("load_skill", {})
    tools = [{"type": "function", "function": {
        "name": t["name"], "description": t.get("description", ""),
        "parameters": t["inputSchema"],
    }} for t in mcp.tools()]

    messages = [{"role": "system", "content": SYSTEM + workflow}]
    # Optionally prime the context with a prior report (repeatable) so this run
    # builds on earlier findings instead of starting from scratch.
    for path in args.ingest:
        try:
            report = open(path, encoding="utf-8").read()[:MAX_RESULT]
        except OSError as e:
            sys.exit("could not read --ingest file %s: %s" % (path, e))
        print("  ↳ ingesting prior report: %s" % path, file=sys.stderr, flush=True)
        messages.append({"role": "user", "content":
            "Prior report to build on (from %s). Treat its findings as leads to "
            "reconfirm or extend with fresh evidence, not as ground truth:\n\n%s"
            % (os.path.basename(path), report)})
    messages.append({"role": "user", "content": request})

    loaded = set()
    nudges = 0
    repeats = {}          # tool-call signature -> count, to catch loops
    warned_loops = set()
    try:
        for step in range(args.max_steps):
            metrics["steps"] = step + 1
            resp = llm(cfg, messages, tools)
            metrics["tokens"] += (resp.get("usage") or {}).get("total_tokens", 0) or 0
            if "choices" not in resp:
                print("[stopped: unexpected API reply: %s]" % json.dumps(resp)[:300],
                      file=sys.stderr)
                break
            msg = resp["choices"][0]["message"]
            messages.append(clean_assistant(msg))
            if msg.get("content"):
                metrics["report"] = msg["content"]
                print(msg["content"], flush=True)

            calls = msg.get("tool_calls")
            if not calls:
                # A text-only turn isn't necessarily "done" — models pause to think.
                # Nudge a bounded number of times; only truly stop once closed.
                if metrics["closed"] or nudges >= 5:
                    break
                nudges += 1
                messages.append({"role": "user", "content":
                    "Keep going until you have the answer. Use the tools; "
                    "do not stop mid-task. When truly finished, call browser_close "
                    "and give the final result."})
                continue

            nudges = 0
            loop_sig = None
            for tc in calls:
                fn = tc["function"]
                args_obj = tool_args(fn)
                metrics["tool_calls"] += 1
                metrics["arg_shape"]["dict" if isinstance(fn.get("arguments"), dict)
                                     else "string"] += 1

                # load_skill goes to mulot like any other tool; we only observe it
                # here to record which stacks the model pulled, for the metrics.
                if fn["name"] == "load_skill":
                    for s in (args_obj.get("stacks") or []):
                        loaded.add(s)
                    metrics["stacks"] = sorted(loaded)

                # Isolate the traffic journal so parallel runs don't share one DB.
                if fn["name"] == "browser_launch" and args.journal and "journal_db" not in args_obj:
                    args_obj["journal_db"] = args.journal
                # MULOT_HEADLESS is the human's override (e.g. =false to watch the
                # run). But the model routinely passes headless:true anyway — the
                # tool desc and workflow nudge it — and an explicit arg beats the
                # env var inside mulot. So when the env is set, drop the model's
                # guess and let mulot's envcfg resolve MULOT_HEADLESS authoritatively.
                if fn["name"] == "browser_launch" and os.environ.get("MULOT_HEADLESS"):
                    args_obj.pop("headless", None)
                if fn["name"] == "browser_close":
                    metrics["closed"] = True

                # Loop guard: flag a stateful call repeated identically with no
                # new result. Observation tools (snapshot, get_cookies, wait_for,
                # query_dom, screenshot, get_console, get_form_fields) are
                # legitimately repeated after every action, so they are NOT
                # guarded — only HTTP requests and the stateful browser actions
                # (navigate/reload/launch/set_cookie) that a spiralling run hammers.
                sig = None
                if fn["name"].startswith("http_"):
                    sig = "%s %s %s" % (fn["name"], args_obj.get("method", "GET"),
                                        str(args_obj.get("url", ""))[:120])
                elif fn["name"] in ("browser_navigate", "browser_reload",
                                    "browser_launch", "browser_set_cookie"):
                    key = args_obj.get("url") or args_obj.get("value") or ""
                    sig = "%s %s" % (fn["name"], str(key)[:120])
                if sig:
                    repeats[sig] = repeats.get(sig, 0) + 1
                    if repeats[sig] >= 4 and sig not in warned_loops:
                        warned_loops.add(sig)
                        loop_sig = sig

                print("  ↳ %s %s" % (fn["name"], json.dumps(args_obj)),
                      file=sys.stderr, flush=True)
                out = mcp.call(fn["name"], args_obj)
                metrics["tool_usage"][fn["name"]] = metrics["tool_usage"].get(fn["name"], 0) + 1
                if out.startswith("ERROR:"):
                    metrics["tool_errors"][fn["name"]] = metrics["tool_errors"].get(fn["name"], 0) + 1
                    if len(metrics["error_samples"]) < 20:
                        metrics["error_samples"].append("%s: %s" % (fn["name"], out[7:207]))
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": out})

            if loop_sig:
                messages.append({"role": "user", "content":
                    "You've repeated the same action (%s) several times with no "
                    "new result. STOP repeating it. Read the latest state first "
                    "(http_flow_body for a request, or browser_snapshot for the "
                    "page), then decide whether the finding is CONFIRMED by "
                    "concrete evidence (command output, file contents, a reflected "
                    "marker, a differential). If it is not, CHANGE the technique / "
                    "payload structure / file path / vuln class, or report it as "
                    "an UNCONFIRMED lead — do not resend the same call." % loop_sig})
        else:
            print("[stopped: max-steps=%d reached]" % args.max_steps, file=sys.stderr)
    except Exception as e:  # noqa: BLE001 - record and still emit metrics
        metrics["error"] = str(e)
        print("[error] %s" % e, file=sys.stderr)
    finally:
        mcp.close()
        metrics["wall_s"] = round(time.time() - t0, 1)
        metrics["loops"] = len(warned_loops)
        metrics["ok"] = bool(metrics["closed"] and metrics["report"] and not metrics["error"])
        if args.out:
            try:
                json.dump(metrics, open(args.out, "w"), indent=2)
            except OSError as e:
                print("[warn] could not write --out: %s" % e, file=sys.stderr)


if __name__ == "__main__":
    main()
