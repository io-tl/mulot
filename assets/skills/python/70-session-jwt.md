# Signed cookies & JWT — Flask sessions, itsdangerous, JWT

Python apps authenticate with client-side signed tokens. If the signing key is
weak/known/leaked (e.g. via DEBUG traceback, `{{config}}` SSTI, or `../app.py`
read), you forge an admin session. Do all encode/decode/HMAC inside
`browser_evaluate_js` (`atob`/`btoa`, `crypto.subtle`, the byte↔hex↔base64
helper).

## Flask / itsdangerous session cookie
Format: `<base64url(payload)>.<base64url(timestamp)>.<base64url(hmac_sig)>`,
e.g. `eyJ1c2VyIjoiYm9iIn0.aBcD.xxxxx`. The leading segment base64url-decodes to
JSON (NOT encrypted) — decode it with `browser_evaluate_js` to read
`{"user":..., "admin":false, ...}`.
- **Decode**: split on `.`, base64url-decode segment 0 → inspect claims.
- **Key known/guessed**: Flask signs with HMAC-SHA1 over a derived key
  (`itsdangerous` salt `"cookie-session"`, key = SECRET_KEY). If you recovered
  SECRET_KEY, recompute the signature over your tampered payload with
  `crypto.subtle` HMAC and assemble a new cookie; set it via
  `browser_set_cookie{name:"session",...}` (or send in `http_request` cookies)
  and replay an authed page. Flip `admin`/`user_id` and confirm escalation.
- **Key unknown**: weak keys (`dev`, `secret`, `changeme`, `CHANGE_ME`) are
  brute-forceable — sweep candidate keys: for each, HMAC the known payload and
  compare to the captured signature (one `browser_evaluate_js` loop, return the
  matching key). A 32+ byte random key is not guessable — report only if weak.

## JWT (`Authorization: Bearer <jwt>` or a cookie)
Decode header+payload (base64url) with `browser_evaluate_js`.
- **alg:none**: set header `{"alg":"none"}`, drop the signature, replay via
  `http_request` headers. Accepted ⇒ auth bypass.
- **Weak HMAC secret** (`HS256`): brute candidate secrets by recomputing the
  signature with `crypto.subtle`; on a hit, forge any claims (`role:admin`,
  `sub:1`) and replay.
- **alg confusion** (`RS256`→`HS256`): if the public key is fetchable, sign with
  it as the HMAC secret.
- **kid injection**: if the header carries `kid` (key id) used server-side to
  look up the signing key, try path traversal (`kid:"../../../../dev/null"`,
  then sign with an EMPTY HMAC secret via `crypto.subtle`) or SQLi
  (`kid:"' UNION SELECT 'attacker-secret'-- "`, then sign with that known
  string). A 200 on the re-signed token ⇒ the app trusts client-controlled key
  material. (jku/x5u header injection needs an attacker-reachable URL — true
  OOB; skip unless the app exposes a URL-fetching field you can chain.)
- **Claim tampering**: change `exp`, `role`, `user_id`; replay and compare.

Evidence: forged cookie/JWT + an authed response it unlocks (admin page/data).
Remediation: long random `SECRET_KEY` from env (never in source/DEBUG output);
pin the JWT `alg`; verify signature server-side; rotate keys on leak; prefer
server-side sessions for sensitive state.
