# Auth, session & JWT (Node)

## Session cookies
- `connect.sid` (express-session) should be `HttpOnly` + `Secure` + `SameSite`;
  flag any missing flag (`browser_get_cookies`). It is signed with a secret — a
  default/weak `session secret` (e.g. `keyboard cat`) lets you forge it.
- **Fixation**: does the cookie rotate on login? Compare `browser_get_cookies`
  before vs after `scan_login`. No rotation ⇒ fixation.
- **Default/weak creds & no lockout**: `scan_login` with a `success_indicator`
  and `isolate_session:true`; spray with `http_fuzz` (password list in the JSON
  body, `match_status:200`) when nothing locks out.

## JWT (very common in Node APIs)
Grab the token (cookie or `Authorization: Bearer`), decode it in
`browser_evaluate_js` (`atob` the two parts; JWT helper in its description). Then:
1. **alg:none** — set header `{"alg":"none","typ":"JWT"}`, escalate claims
   (`"role":"admin"`), drop the signature (trailing `.`). Replay with
   `http_request(headers:{"Authorization":"Bearer <forged>"})`. Accepted ⇒ bypass.
2. **Weak HMAC secret** — brute HS256 offline: in `browser_evaluate_js` recompute
   `HMACSHA256(header.payload, guess)` with `crypto.subtle` over a wordlist
   (`secret`, `password`, `jwt`, `changeme`, the app name...) until it matches the
   token's signature. Found ⇒ forge any claims.
   Predictable secrets beat brute force: check the fingerprint's `.env`/config
   forced-browse hits (`10-fingerprint.md`) and the app/company name first —
   `<app>_secret`, `<app>2024`, values seen in an exposed repo/config — before a
   generic wordlist sweep.
3. **RS256→HS256 confusion** — if the server verifies with a public key, change
   `alg` to `HS256` and sign with the PUBLIC KEY bytes as the HMAC secret
   (`crypto.subtle`). Accepted ⇒ full forge.
4. **Claim tampering** — swap `sub` / `role` / `isAdmin`; expired `exp` still
   accepted.
5. **`kid` header injection** — if `kid` selects the verification key from a
   file or DB:
   - Path traversal to a predictably-empty file, so the "key" is `""`:
     `kid:"../../../../../../dev/null"`. If a dot-segment filter blocks `..`,
     skip traversal entirely and send a bare absolute path — `kid:"/dev/null"` —
     many Node apps resolve it with `path.resolve(keysDir, kid)`, which DISCARDS
     `keysDir` for an absolute `kid` (unlike `path.join`), so the dot-filter
     never even triggers.
   - SQLi in the DB-backed lookup: `kid:"x' UNION SELECT 'knownsecret'-- -"` —
     sign with `knownsecret`.
   Re-sign header+payload with the resulting key (`crypto.subtle` in
   `browser_evaluate_js`), replay with `http_request`, compare to the untampered
   response.

## IDOR / broken access control
Capture an authed request (`http_history`), replay with `http_request from_flow`
using another user's `cookies`/token (or `use_session:false`). Still returns the
data ⇒ broken access control. Enumerate ids with `http_fuzz` (marker on the id).

Evidence: the forged token/request + the authenticated response it unlocks.
Remediation: strong random `session secret`; pin the JWT `alg` (no `none`, no
HS/RS confusion), strong/rotated keys, verify `exp`; server-side authorization on
every object.
