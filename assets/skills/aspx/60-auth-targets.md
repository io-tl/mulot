# Reaching authenticated targets (.NET)

Pick the auth mechanism BEFORE testing and use the clean primitive — don't bury
credentials in a `fetch` URL.

## Forms authentication (cookie `.ASPXAUTH`)
`scan_login` (with a `success_indicator`, `isolate_session=true`). After login
every tool and same-origin fetch carries the cookie automatically.

## Windows auth / NTLM / Negotiate
A `WWW-Authenticate: Negotiate`/`NTLM` on a 401 (read via `http_flow`) means
integrated auth. Send credentials with `http_request`
`headers:{"Authorization":"NTLM <base64>"}` if you have a hash/ticket; otherwise
note it and pivot to other surfaces.

## HTTP Basic
`http_request(url, use_session:false,
headers:{"Authorization":"Basic <base64(user:pass)>"})` — no navigation needed.

## Bearer / JWT (ASP.NET Core)
`Authorization: Bearer <token>` via `http_request` headers. To tamper
(`alg:none`, weak HS256 secret, claim/role swap), build the new token in
`browser_evaluate_js` and replay; compare to the untampered response.

## WebForms login is a POSTback
The login button posts `__VIEWSTATE` + `__EVENTVALIDATION` +
`__VIEWSTATEGENERATOR` + the textbox names. To brute force / spray:
1. Capture one real login POST with `http_history` → note the flow id.
2. `http_fuzz from_flow:<id>` with the marker on the password field inside the
   captured `body` (e.g. `...&txtPassword=FUZZ&...`), a password list as
   `payloads`, and `match_regex` on a success string (or absence of the failure
   text). The valid `__VIEWSTATE`/`__EVENTVALIDATION` ride along from the flow.

Rule: the moment a request needs an Authorization/Cookie header you control, use
`http_request` (full header control, no CORS) over the browser's implicit auth.
