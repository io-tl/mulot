# Auth, session, JWT & access control (Java)

## Reaching authenticated targets
- **Form login**: `scan_login` with a `success_indicator` (e.g. `a[href*=logout]`)
  and `isolate_session=true`; later tools/fetches carry the `JSESSIONID`.
- **HTTP Basic**: `http_request(url, use_session:false,
  headers:{"Authorization":"Basic <base64(user:pass)>"})`.
- **Bearer/JWT**: `Authorization: Bearer <token>` via `http_request` headers.

## Session hygiene (`browser_get_cookies` / `http_flow` Set-Cookie)
`JSESSIONID` should be `HttpOnly` + `Secure` + `SameSite`. Flag any missing flag.
Does it rotate on login? Compare before/after `scan_login` — no rotation ⇒ session
fixation. `;jsessionid=` in URLs ⇒ session-id leakage.

## JWT tampering (decode in `browser_evaluate_js`, base64url the 3 parts)
- **alg:none**: set header `{"alg":"none"}`, drop the signature, flip a claim
  (`"role":"admin"`), replay with `http_request`. Accepted ⇒ broken.
- **Weak HMAC secret**: brute the secret with `http_fuzz` (or offline), re-sign via
  `crypto.subtle` HMAC in `browser_evaluate_js`. Common: `secret`, `changeit`.
- **alg confusion (RS256→HS256)**: sign with the public key as the HMAC key.
- **Claim/kid injection**: tamper `kid` (path traversal / SQLi), `iss`, `sub`.

## Key-injection headers
- **jku/x5u need a URL you host — mulot cannot host one.** Don't chase this
  blindly; check but expect a dead end unless an internal/attacker-reachable
  URL already exists.
- **Embedded `jwk` (self-signed, no hosting needed)** — the realistic in-band
  attack: generate a keypair in `browser_evaluate_js` (on `about:blank` if the
  target is plain `http://` non-localhost — `crypto.subtle` needs a secure
  context):
  `crypto.subtle.generateKey({name:"RSASSA-PKCS1-v1_5",modulusLength:2048,
  publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["sign","verify"])`,
  export the public part (`crypto.subtle.exportKey("jwk",pub)`), build header
  `{"alg":"RS256","typ":"JWT","jwk":{kty,n,e,...}}`, sign `header.payload` with
  the private key (`crypto.subtle.sign`), replay with `http_request`. Accepted
  ⇒ the server trusts an attacker-supplied key in-band. Try `x5c` (self-signed
  cert chain) the same way if `jwk` is ignored.
- **kid path traversal — try several encodings** before giving up: bare
  `../../../../dev/null`, doubled slash `....//....//dev/null`, single-encoded
  `%2e%2e%2f%2e%2e%2fdev%2fnull`, double-encoded `%252e%252e%252f`, absolute
  `/dev/null` (Windows: `NUL`). Empty/known content at that path ⇒ sign HS256
  with that content (often the empty string).

## Brute force / spraying (no lockout)
`http_fuzz` with the marker in the password (`body:"username=admin&password=FUZZ"`)
or a Basic-auth header, a password list, `match_status`/`match_regex` on a success
string. Try container defaults: `tomcat/tomcat`, `admin/admin`, `weblogic/welcome1`.

## IDOR / broken access control
Capture an authenticated request (`http_history`), replay with `http_request`
`from_flow` and `use_session:false` (or another user's `cookies`). Still returns
data ⇒ broken access control. Enumerate ids with `http_fuzz` (marker on the id).

Evidence: the request/response showing the bypass (tampered token, missing flag,
cross-user data).
Remediation: validate JWT alg + signature server-side (reject `none`, strong/rotated
keys), secure `JSESSIONID` flags + `changeSessionId()` on login, per-form CSRF
tokens, and method-level authorization (`@PreAuthorize`) on every object.
