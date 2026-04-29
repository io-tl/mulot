# Auth, session & CSRF (PHP)

- **Default/weak credentials**: `scan_login` with a `success_indicator`
  (e.g. `a[href*=logout]`) and `isolate_session=true`. Try admin/admin,
  admin/password, common pairs.
- **No lockout / user enumeration**: replay the login several times with
  `http_request`; if wrong credentials never lock out and the message
  differs for a valid vs invalid user, it is brute-forceable and enumerable.
- **Session cookie hygiene** (`browser_get_cookies`): `PHPSESSID` should be
  `HttpOnly` + `Secure` + `SameSite`. Flag any missing flag. A persistent
  (non-session) `PHPSESSID` with a far-future expiry is a finding.
- **Session fixation**: does `PHPSESSID` rotate on login? Compare the cookie
  before and after `scan_login`. No rotation ⇒ fixation risk.
- **CSRF**: for state-changing forms (change password/email), check
  `browser_get_form_fields` for an anti-CSRF token (`user_token`, `_token`,
  `csrf`...). Absent ⇒ CSRF. Do NOT actually change the admin password.
- **IDOR / broken access control**: capture an authenticated request
  (`http_history`), then `http_request` with `from_flow` and `use_session=false`
  or another user's `cookies`. If it still returns the data, access control is
  broken. To enumerate ids, `http_fuzz` with a marker on the id and a payload
  range.

Evidence: the request/response showing the weakness.
Remediation: secure cookie flags, `session_regenerate_id(true)` on login,
per-form CSRF tokens, and server-side authorization checks on every object.
