# JWT attack surface — capability

Load whenever the target uses a JSON Web Token, whatever the backend: an
`Authorization: Bearer eyJ...` header, an `eyJ`-prefixed cookie, or a
`/token`/`/login` JSON response containing one. Decode/forge entirely in
`browser_evaluate_js` (atob the 3 base64url parts; the byte↔hex↔base64 helper
is in the tool's description); replay with `http_request` headers.

1. **Decode**: split on `.`, base64url-decode header + payload (pad with `=`,
   swap `-_`→`+/` first) — read `alg`, `kid`, `iss`, and the claims (`role`,
   `sub`, `exp`, `admin`). Note the `alg` and whether `kid`/`jku`/`x5u` appear.
2. **alg:none**: rewrite the header `{"alg":"none","typ":"JWT"}`, keep/escalate
   the claims, DROP the signature (token ends in a bare `.`). Replay via
   `http_request(headers:{"Authorization":"Bearer <forged>"})`. Accepted ⇒ bypass.
3. **Weak HS256 secret**: recompute `HMAC-SHA256(header.payload, guess)` with
   `crypto.subtle` inside `browser_evaluate_js`, looping a candidate list
   (`secret`, `changeme`, `password`, the app/vendor name, `jwt_secret`) and
   comparing to the captured signature — a hit lets you forge ANY claim.
4. **alg confusion (RS256→HS256)**: fetch the RSA public key (`/.well-known/jwks.json`,
   `/jwks`, `/oauth/token_key`, or the TLS cert), set `alg:"HS256"`, and HMAC-sign
   with the PEM/DER public-key bytes as the secret via `crypto.subtle`. If the
   verifier doesn't pin the algorithm, it checks the signature with the same
   public key it trusts — and accepts it.
5. **`kid` injection**: if the header carries `kid` (a filename/path used to
   look up the verification key), try path traversal to a predictable-content
   file (`"kid":"../../../../../../dev/null"`, or a static asset) and sign HS256
   with that file's (empty/known) bytes as the secret; also try SQLi in `kid`
   (`"kid":"x' UNION SELECT 'known-secret'-- -"`) if it feeds a DB lookup.
6. **`jku`/`x5u`**: if present, they tell the server to FETCH a JWKS/cert from a
   URL you supply — needs a listener you control (mulot has none); note as an
   UNCONFIRMED lead unless the app also exposes an internal/attacker-writable
   URL you can point it at in-band.
7. **Claim tampering** on an otherwise-valid token (unchecked `exp`, `aud`,
   `iss`, or a signature-check bug): mutate one claim at a time and replay.

Evidence: the forged/tampered token + the authenticated response it unlocks
(admin page, another user's data).
Remediation: pin the algorithm server-side (reject `none`, never accept
HS-signed tokens on an RS-configured verifier), long random rotated secrets /
proper key management, validate `kid` against an allowlist (never path/SQL
lookup), pin `jku`/`x5u` to a fixed host, verify `exp`/`aud`/`iss` on every use.
