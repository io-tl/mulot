# Reaching authenticated targets

Pick the auth mechanism BEFORE testing, and use the clean primitive — don't put
credentials in a `fetch` URL (the browser caches Basic auth inconsistently and it
bites you mid-attack).

## Cookie / session (Django, Flask)
`scan_login` (with a `success_indicator`, `isolate_session=true`) — then every
tool and same-origin fetch carries the session automatically. Django login also
needs the `csrfmiddlewaretoken` hidden field + `csrftoken` cookie; `scan_login`
submits the real form so it handles this. To replay manually, read the
`csrftoken` cookie with `browser_get_cookies` and send it as both a
`X-CSRFToken` header and the form field via `http_request`.

## Bearer / JWT (FastAPI, DRF)
`Authorization: Bearer <token>` via `http_request` headers for FastAPI and
DRF's `djangorestframework-simplejwt`. Plain DRF `TokenAuthentication` (the
built-in, non-JWT scheme) instead uses `Authorization: Token <key>` — try both
schemes before concluding a captured key is invalid. Obtain the token from
the login/`/token` endpoint (POST creds, read the JSON), then carry it. To tamper
(alg:none, weak secret, claim swap) see skill: session-jwt and replay the new
token the same way; compare against the untampered response.

## HTTP Basic / Digest
Send the header explicitly with `http_request` (works without navigating, full
response):

    http_request(
      url, use_session:false,
      headers:{"Authorization":"Basic <base64(user:pass)>"}
    )

To make the *browser* authenticated for navigation/snapshots, navigate once to
`http://user:pass@host/` to prime it; thereafter same-origin
`fetch(..., {credentials:"include"})` inside `browser_evaluate_js` carries it.

## API key
Header (`X-API-Key`, `Authorization: Api-Key ...`) or query param via
`http_request`.

## Brute force / credential spraying
When there's no lockout, spray with `http_fuzz` instead of one login at a time:
marker in the password field of the POST body
(`body:"username=admin&password=FUZZ&csrfmiddlewaretoken=<tok>"`) or in a
Basic-auth header, a password list as `payloads`, and `match_status` (or
`match_regex` on a success string / absence of the error message) to flag the
hit. Read the `length`/`status` column for the odd-one-out.

Rule: the moment a request needs an Authorization/Cookie/CSRF header you control,
use `http_request` (full header control, no CORS) rather than fighting the
browser's implicit auth.
