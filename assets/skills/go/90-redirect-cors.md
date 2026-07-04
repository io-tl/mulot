# Open redirect & insecure CORS (Go)

## Open redirect
`http.Redirect(w, r, userValue, 302)` with a user-controlled destination. Params:
`?next=`, `?return`, `?returnTo`, `?redirect`, `?url`, `?continue`, `?dest`,
`?callback` — usually on login/logout/OAuth flows.
- Test `?next=https://evil.example/` with `http_request(follow_redirects:false)`
  and read the `Location` header (from the response or `http_flow`). Off-site ⇒
  open redirect.
- Sweep filter bypasses in ONE `http_fuzz` (marker in the param,
  `match_regex:"evil\\.example"` on the Location):
  `payloads:["https://evil.example","//evil.example","/\\/evil.example",
  "https:/evil.example","https://target.com.evil.example","%2f%2fevil.example",
  "\\/\\/evil.example","https://evil.example%5c@target.com"]`. Protocol-relative
  `//host` and backslash tricks beat a naive `strings.HasPrefix(v,"/")` check.

## CORS
Read response headers (`http_flow` / `scan_passive`). Misconfig patterns:
- `Access-Control-Allow-Origin` REFLECTING the request `Origin` together with
  `Access-Control-Allow-Credentials: true` ⇒ any site can read authed responses.
  Confirm: `http_request` with `headers:{"Origin":"https://evil.example"}` and
  check the response echoes that origin back with credentials allowed.
- `Access-Control-Allow-Origin: *` on an authenticated/JSON API (less severe
  without credentials — still note it).
- Weak origin checks: `Origin: https://target.com.evil.example` or
  `https://eviltarget.com` accepted by a naive suffix/substring match — test each
  via the `Origin` header in `http_request`.
- `Origin: null` (sandboxed iframe, `data:`/`file:` page, or a bare redirect
  chain) accepted and echoed with credentials ⇒ any sandboxed attacker page
  reads authed responses. Test via `http_request headers:{"Origin":"null"}`
  the same way as the other origin checks.

Evidence: the `Location` / `Access-Control-Allow-Origin` response header proving
the off-site redirect or the attacker origin was honored.
Remediation: redirect only to a server-side allowlist or relative paths
(parse with `url.Parse`, reject any host change or scheme-relative value); for
CORS, match `Origin` against an exact allowlist and never reflect an arbitrary
origin while allowing credentials.
