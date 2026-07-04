# CORS misconfiguration & open redirect — capability

Both bugs turn a response HEADER into the vulnerability — read `http_flow` /
`scan_passive` headers on every response, whatever the backend stack.

## Open redirect
Look for a redirect-destination param: `?next=`, `?return`/`?returnTo`,
`?redirect`/`?redirect_uri`, `?url`, `?continue`, `?dest`, `?callback` — login,
logout, and OAuth flows are the classic spots.
1. Baseline: set it to `https://evil.example/` and read the 3xx `Location` with
   `http_request(follow_redirects:false)` (or `http_flow`/`http_history(status:302)`).
   An off-host `Location` ⇒ open redirect.
2. Sweep bypasses in ONE `http_fuzz` (marker in the param,
   `match_regex:"evil\\.example"` on the Location):
   `payloads:["https://evil.example","//evil.example","/\\/evil.example",
   "https:evil.example","https://target.tld@evil.example","https://target.tld.evil.example",
   "%2f%2fevil.example","https://evil.example%5c@target.tld","/%09/evil.example"]`.
   Protocol-relative, backslash, and userinfo-`@` tricks beat naive prefix checks.

## CORS misconfiguration
Replay any authenticated request with an attacker `Origin` header
(`http_request(headers:{"Origin":"https://evil.example"})`) and read the
response:
- `Access-Control-Allow-Origin` REFLECTING that `Origin` + `Access-Control-
  Allow-Credentials: true` ⇒ any site can read authenticated responses — the
  most severe case.
- `Origin: null` accepted (sandboxed iframe / file:// origin bypass) — test it
  explicitly, some allowlists special-case it wrongly.
- A naive suffix/substring allowlist: try `https://target.tld.evil.example` and
  `https://eviltarget.tld` as `Origin` and see which one is wrongly accepted.
- `Access-Control-Allow-Origin: *` on a credentialed/JSON API — less severe
  alone, still a finding.

Evidence: the off-host `Location` header, or the reflected `Access-Control-
Allow-Origin` + credentials-allowed response to a forged `Origin`.
Remediation: redirect only to a same-host allowlist or relative paths (reject
any scheme/host change); match `Origin` against an exact allowlist server-side
and never reflect an arbitrary value while `Access-Control-Allow-Credentials`
is true; never trust `null`.
