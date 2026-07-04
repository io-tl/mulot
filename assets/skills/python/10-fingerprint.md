# Fingerprint a Python stack

Confirm Python and identify the framework/server/version to choose targeted
tests. Gather signals with `browser_navigate`, `browser_get_cookies`,
`scan_passive` (its `headers` section), and `http_request`.

- **Cookies**: `sessionid` + `csrftoken` ⇒ Django. `session=eyJ...` (signed,
  dot-separated) ⇒ Flask/Werkzeug `itsdangerous` (see skill: session-jwt).
  `_xsrf` ⇒ Tornado. `connect.sid` ⇒ not Python (Express).
- **Headers**: `Server: Werkzeug/x.y Python/3.z` (Flask dev), `gunicorn`,
  `uvicorn` (ASGI/FastAPI), `WSGIServer` (Django dev). `X-Powered-By` rarely set
  but record it. Cookie flags on `Set-Cookie` (HttpOnly/Secure/SameSite).
- **Framework consoles & docs** (probe with `http_request`):
  - FastAPI: `/docs` (Swagger UI), `/redoc`, `/openapi.json` (full route +
    schema dump — a finding if public).
  - Django: `/admin/` (login page ⇒ Django admin), `/static/`, `/__debug__/`
    (django-debug-toolbar).
  - Flask/Werkzeug interactive debugger: a 500 page titled **"Werkzeug
    Debugger"** with a `/console` and traceback frames ⇒ `DEBUG=True` (skill:
    debugger-rce — often RCE).
- **DEBUG=True tracebacks**: trigger a 500 (bad type in a param, bad route) and
  read the body with `http_flow_body` on the error flow. Django DEBUG shows a
  yellow traceback page leaking settings, installed apps, SQL, env vars.
- **Pydantic validation errors** confirm FastAPI even when `/docs`/
  `/openapi.json` are disabled: a malformed body/param returns 422 with
  `{"detail":[{"loc":[...],"msg":...,"type":...}]}` — trigger one with
  `http_request` (wrong type/missing required field) and read `http_flow_body`.
- **Forced-browse common files** in ONE `http_fuzz`: `url:"http://host/FUZZ"`,
  `match_status:200`, `payloads:[".env","app.py","wsgi.py","settings.py",
  "manage.py","requirements.txt","__pycache__/","static/","admin/","docs",
  "openapi.json",".git/config",".dockerenv"]`. Each 200 row is a finding.

Record: framework + version, server, whether DEBUG is on (high severity), any
exposed `/openapi.json` / `/docs` / `/admin/` / source file (each a finding), and
`Server` banner disclosure (low — strip it).
