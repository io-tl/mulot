# Auth, session, CSRF & access control (Rails/Sinatra)

Pick the auth mechanism before testing and use the clean primitive — the moment a
request needs an Authorization/Cookie header you control, use `http_request`
(full header control, no CORS) rather than fighting the browser's implicit auth.

## Login / credentials
- **Cookie session**: `scan_login` with a `success_indicator`
  (e.g. `a[href*=logout]` or `a[href*=sign_out]`), `isolate_session=true`. Try
  admin/admin, admin@example.com/password, common pairs. Devise apps use
  `user[email]` / `user[password]` and `/users/sign_in`.
- **HTTP Basic** (often guards `/sidekiq`, staging): send the header explicitly:
  `http_request(url, use_session:false, headers:{"Authorization":"Basic <b64(user:pass)>"})`.
- **No lockout / user enumeration**: replay login with `http_request`; if wrong
  creds never lock out and the message differs for a valid vs invalid email,
  it's brute-forceable and enumerable. Spray with `http_fuzz`: marker in the
  password (`body:"user[email]=admin@x&user[password]=FUZZ&authenticity_token=<tok>"`),
  a password list, `match_status:302` (or `match_regex` on absence of the error).

## Session cookie hygiene (`browser_get_cookies`)
`_<app>_session` should be `HttpOnly` + `Secure` + `SameSite=Lax/Strict`. Flag
any missing flag. Check rotation on login (session fixation): compare the cookie
before vs after `scan_login` — no rotation ⇒ fixation risk. Decode/forge it in
skill: session-cookie-crypto.

## CSRF
Rails uses a per-session `authenticity_token` (hidden field + `<meta
name="csrf-token">`) with `protect_from_forgery`. For a state-changing form
(change email/password), `browser_get_form_fields` and confirm the token exists
and is verified: replay the captured POST with `http_request from_flow` but
**omit/blank** `authenticity_token`. If it still succeeds (422 not raised), CSRF
protection is off (`skip_before_action :verify_authenticity_token`, or
`protect_from_forgery with: :null_session`). Sinatra needs `Rack::Protection`
explicitly — often missing. Do NOT actually change admin creds.

## IDOR / broken access control
Capture an authenticated request (`http_history` → `http_flow`), then
`http_request from_flow` with `use_session:false` or another user's `cookies`.
If it still returns the data, authorization is missing (no Pundit/CanCanCan
check, raw `Model.find(params[:id])`). Enumerate ids with `http_fuzz` (marker on
the `/users/FUZZ` id, a numeric range; watch status/length). Try `params[:id]`
swaps on nested resources too.

Evidence: the request/response showing the weakness (logged-in proof, token-less
write accepted, or another user's record returned).
Remediation: secure cookie flags + `reset_session` on login; keep
`protect_from_forgery` (no blanket `skip`); enforce per-object authorization
(Pundit/CanCanCan, scope by `current_user`); add rate-limiting/lockout
(`Rack::Attack`, Devise lockable).
