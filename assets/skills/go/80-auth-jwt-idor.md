# Auth: JWT, sessions, IDOR, mass assignment (Go)

## JWT
Go apps commonly use `golang-jwt/jwt`. Grab the token (`browser_get_cookies`, an
`Authorization: Bearer` in `http_history`, or a `token`/`jwt` cookie). Decode the
3 base64url parts in `browser_evaluate_js` (`atob` after `-_`→`+/`).
- **alg:none**: set header `{"alg":"none","typ":"JWT"}`, keep the claims, empty
  signature (token ends in `.`). Misconfigured verifiers accept it. Forge in
  `browser_evaluate_js`, replay via `http_request` headers, compare responses.
- **Weak HMAC secret**: if `alg:HS256`, brute the secret — recompute the
  signature with `crypto.subtle` HMAC-SHA256 over `header.payload` in
  `browser_evaluate_js` for each candidate (sweep a wordlist) until it matches.
  Then forge an elevated claim (`"role":"admin"`, `"sub":"1"`) and replay.
- **Source the public key first**: `http_request` GET `/.well-known/jwks.json`
  or `/.well-known/openid-configuration` (read `jwks_uri`, fetch it) — the
  `n`/`e` (or `x5c` cert) under the token's `kid` IS the key material. No
  JWKS? Pull it from the TLS cert or an `/oauth/certs`-style path. Try both
  the raw key bytes AND its PEM form as the HMAC secret — a format mismatch
  makes a correct attack look like it failed.
- **alg confusion (RS→HS)**: server uses RSA? Try signing with its PUBLIC key
  bytes as the HMAC secret — if the lib doesn't pin the alg, it verifies.
- **kid/jku/x5u injection**: if the header carries `kid` and the verifier's
  `Keyfunc` looks it up (file/DB), try path traversal
  (`kid:"../../../../dev/null"` ⇒ empty key, HMAC-sign with an empty secret)
  or `kid:"' UNION SELECT 'attacker-secret'--"` if the lookup looks
  SQL-backed. If the header carries `jku`/`x5u` (a key-server URL), point it
  at a URL you control (or the app's own echo/upload endpoint) and sign with
  your own key — forge in `browser_evaluate_js`, replay via `http_request`.
- **Unchecked claims**: tamper `exp`/`role`/`sub`/`aud` and see what's accepted.

## Sessions & cookies
`browser_get_cookies`: session cookie should be `HttpOnly`+`Secure`+`SameSite`.
gorilla `securecookie` needs proper hash/block keys — a short/predictable value
is a flag. Does the cookie rotate on login (else fixation)? Compare before/after
`scan_login`.

## IDOR / broken access control
Numeric/sequential ids everywhere (`/api/v1/users/1`, `?order=1001`). Capture an
authed request (`http_history`), then `http_request from_flow` with another
user's `cookies` (or `use_session:false`). Still returns the data ⇒ broken authz.
Enumerate with `http_fuzz`: marker on the id, payload range `1..200`, read
length/status to spot ids returning other users' objects.

## Mass assignment / over-binding
Gin `c.ShouldBindJSON(&user)` / Echo `c.Bind(&u)` bind ANY JSON key matching a
struct field. If the model has `IsAdmin`/`Role`/`Balance`/`Verified`, a normal
update endpoint may let you set them. Replay a profile-update request
(`http_request from_flow`) with extra keys `{"is_admin":true,"role":"admin"}`;
check whether the privilege sticks on the next read.

Evidence: the forged/tampered request + the response showing elevated access or
another user's data.
Remediation: pin the JWT alg server-side and use a strong, rotated secret/key;
bind to explicit allow-listed DTOs (never the DB model); enforce per-object
authz in every handler; set secure flags and rotate session cookies on login.
