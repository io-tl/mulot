# Reaching authenticated targets

Pick the auth mechanism BEFORE testing, and use the clean primitive — don't put
credentials in a `fetch` URL (the browser caches Basic auth inconsistently and
it bites you mid-attack).

## HTTP Basic / Digest
Send the header explicitly with `http_request` (works without even
navigating, and you read the full response):

    http_request(
      url, use_session:false,
      headers:{"Authorization":"Basic <base64(user:pass)>"}
    )

To make the *browser* authenticated for normal navigation/snapshots, navigate
once to `http://user:pass@host/` to prime it; thereafter same-origin
`fetch(..., {credentials:"include"})` inside `browser_evaluate_js` carries it.

## Cookie / session
`scan_login` (with a `success_indicator`, `isolate_session=true`) — then
every tool and same-origin fetch carries the session automatically.

## Bearer / JWT
`Authorization: Bearer <token>` via `http_request` headers. To tamper
(alg:none, weak secret, claim swap), build the new token and replay it the same
way; compare the response to the untampered one.

## API key
Header (`X-API-Key`) or query param via `http_request`.

## Brute force / credential spraying
When there's no lockout, spray with `http_fuzz` instead of one login at a time:
marker in the password field of the POST body (`body:"username=admin&password=FUZZ"`)
or in a Basic-auth header, a password list as `payloads`, and `match_status` (or
`match_regex` on a success string / absence of the error message) to flag the hit.
Read the `length`/`status` column for the odd-one-out.

Rule: the moment a request needs an Authorization/Cookie header you control, use
`http_request` (full header control, no CORS) rather than fighting the
browser's implicit auth.
