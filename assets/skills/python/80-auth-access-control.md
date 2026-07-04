# Auth, sessions, CSRF & access control (Python)

- **Default/weak credentials**: `scan_login` with a `success_indicator`
  (e.g. `a[href*=logout]`) and `isolate_session=true`. Try admin/admin,
  admin/password, and Django's common `admin` superuser pairs. The Django admin
  lives at `/admin/`.
- **Session cookie hygiene** (`browser_get_cookies`): Django `sessionid` and
  `csrftoken` should be `HttpOnly`(sessionid) + `Secure` + `SameSite`. Flask
  `session` likewise. Flag any missing flag. `SESSION_COOKIE_SECURE=False` /
  `csrftoken` without `Secure` are findings.
- **Session fixation**: does `sessionid` rotate on login? Compare the cookie
  before and after `scan_login`. No rotation ⇒ fixation risk.
- **CSRF**: Django enforces a `csrfmiddlewaretoken` hidden field + `csrftoken`
  cookie — check state-changing forms with `browser_get_form_fields`. Missing on
  a POST view (or `@csrf_exempt`) ⇒ CSRF. Flask without Flask-WTF/CSRFProtect is
  unprotected by default. Test by replaying the POST via `http_request` WITHOUT
  the token — accepted ⇒ vulnerable. Do NOT change the admin password.
- **IDOR / broken object-level access**: capture an authed request
  (`http_history`), then `http_request from_flow` with `use_session:false` or
  another user's `cookies`; or sweep the object id with `http_fuzz` (marker on the
  `/users/FUZZ/` or `?id=FUZZ`, a numeric range, `match_status:200`). Still
  returns data ⇒ broken access control. Django views missing `get_queryset`
  ownership filters are classic.
- **Mass assignment / over-posting**: Django `ModelForm` with `fields="__all__"`
  or DRF serializers exposing `is_staff`/`is_superuser`/`is_active`, or
  `Model.objects.update(**request.POST)`. Add extra fields to a profile-update
  POST (`http_request from_flow`, append `is_superuser=true`/`role=admin`) and
  check whether the privilege sticks (re-fetch the profile).
- **Function-level access**: hit admin/staff-only routes (`/admin/`, API
  management endpoints) with a low-priv or no session — 200 ⇒ missing
  `@login_required` / permission check.

Evidence: the request/response showing the bypass (e.g. another user's data, or
`is_superuser` flipped).
Remediation: secure cookie flags + `SESSION_COOKIE_SECURE`/`CSRF_COOKIE_SECURE`;
rotate session id on login; keep CSRF middleware on (no blanket `@csrf_exempt`);
filter querysets by owner; whitelist writable fields (never `fields="__all__"`);
`@login_required`/`permission_required` on every privileged view.
