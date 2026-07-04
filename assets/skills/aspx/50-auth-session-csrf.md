# Auth, session & CSRF (ASP.NET)

- **Default/weak credentials**: `scan_login` with a `success_indicator`
  (e.g. `a[href*=Logout]`) and `isolate_session=true`. Try admin/admin,
  admin/password, sa/sa, common pairs. WebForms login is a postback — see
  skill: auth-targets for the `__VIEWSTATE` spray pattern.
- **Cookie hygiene** (`browser_get_cookies`): `.ASPXAUTH` (Forms auth) and
  `ASP.NET_SessionId` should be `HttpOnly` + `Secure` + `SameSite`. Flag any
  missing flag. `.ASPXAUTH` is encrypted+MAC'd with the `machineKey`; if that
  key leaked (skill: config) the ticket is forgeable — escalate.
- **Session fixation**: does `ASP.NET_SessionId` rotate on login? Compare the
  cookie before and after `scan_login`. No rotation ⇒ fixation risk (ASP.NET
  notoriously keeps the same id; the auth ticket must change instead).
- **No lockout / user enumeration**: replay login with `http_request`; if wrong
  creds never lock out and the message differs for a valid vs invalid user, it
  is brute-forceable and enumerable.
- **CSRF**:
  - MVC: state-changing POSTs need `__RequestVerificationToken`
    (`@Html.AntiForgeryToken` + `[ValidateAntiForgeryToken]`). Check
    `browser_get_form_fields`; absent/unvalidated ⇒ CSRF.
  - WebForms: `__VIEWSTATE` is NOT CSRF protection unless `ViewStateUserKey` is
    set per-user. If only `__VIEWSTATE`/`__EVENTVALIDATION` guard a postback,
    it is likely CSRF-able. Do NOT actually change the admin password.
- **IDOR / broken access control**: capture an authenticated request
  (`http_history`), then `http_request from_flow` with `use_session:false` or
  another user's `cookies`. Still returns the data ⇒ broken authZ. Enumerate
  ids with `http_fuzz` (marker on the id, a range).

Evidence: the request/response showing the weakness.
Remediation: secure cookie flags, rotate the auth ticket on login,
`AntiForgeryToken` + `[ValidateAntiForgeryToken]`, set `ViewStateUserKey`,
server-side authorization on every object, account lockout.
