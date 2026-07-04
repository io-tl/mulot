# SSRF, CORS, mass assignment & misconfig (Node)

## SSRF
Any param the server fetches (`?url=`, `?image=`, webhook, `?proxy=`, PDF/preview
generators using `axios` / `node-fetch` / `request`). Point it inward:
- `http://169.254.169.254/latest/meta-data/` (cloud creds),
  `http://localhost:<port>/`, `http://127.0.0.1`, `file:///etc/passwd`,
  `http://[::1]`,
  `http://2130706433/` (decimal 127.0.0.1), `http://0x7f.0.0.1/` (hex octet) —
  decimal/octal encodings to dodge a naive `127.0.0.1`/`localhost` string filter.
- Send via `http_request`; read the fetched body back in the response. Blind SSRF
  ⇒ timing or an out-of-band host. Sweep targets/ports with one `http_fuzz`.

## CORS misconfig
Replay a request with an attacker `Origin` and read the response headers
(`http_request`, then `http_flow`): if `Access-Control-Allow-Origin` reflects your
`Origin` AND `Access-Control-Allow-Credentials: true`, any site can read authed
responses. Also test `Origin: null` and a `evil.target.com` suffix-match bypass.

## Mass assignment / over-posting
Add fields the form never shows to a JSON body and see if they stick:
`{"username":"x","isAdmin":true,"role":"admin","balance":99999,"verified":true}`
to register / profile-update. Re-read the object; a privileged field that
persisted ⇒ mass assignment.

## ReDoS
A user-controlled string hitting a catastrophic regex (validators, search) hangs
the single-threaded event loop. Send a long evil string (e.g. `"a"*50000+"!"`
against an `(a+)+$`-style pattern) and watch the response time spike — only on a
target you may disrupt.

## Route / dependency disclosure
`package.json` / `package-lock.json` (forced-browse) list every dependency+version
→ map to known CVEs. Probe debug/admin routes: `/debug`, `/admin`, `/api-docs`
(Swagger), `/metrics`, `/.git/`, and source maps (recover server source).

Evidence: the internal/cloud response (SSRF), the reflected ACAO + credentials
header (CORS), the persisted privileged field (mass assignment), or the response
time spike (ReDoS).
Remediation: allowlist outbound hosts + block link-local/loopback (SSRF); strict
Origin allowlist, never reflect-with-credentials (CORS); explicit field allowlists
/ DTOs (mass assignment); bounded/safe regex or `re2` (ReDoS); remove debug routes,
source maps and `package.json` from production; patch vulnerable deps.
