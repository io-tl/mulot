# Reaching authenticated targets (Go)

Pick the auth mechanism BEFORE testing and use the clean primitive — the moment a
request needs an Authorization/Cookie header you control, use `http_request`
(full header control, no CORS) rather than fighting the browser's implicit auth.

## Cookie / session
`scan_login` (with a `success_indicator` like `a[href*=logout]`,
`isolate_session:true`) — afterwards every tool and same-origin fetch carries the
session automatically. Verify with `browser_get_cookies`.

## Bearer / JWT
`Authorization: Bearer <token>` via `http_request` headers. To tamper (alg:none,
weak HMAC secret, claim swap — skill: auth-jwt-idor), forge in
`browser_evaluate_js` and replay the same way; diff against the untampered
response.

## HTTP Basic
`http_request(url, use_session:false, headers:{"Authorization":"Basic <b64>"})` —
build the base64 of `user:pass` in `browser_evaluate_js` (`btoa`). To prime the
browser for normal navigation, navigate once to `http://user:pass@host/`.

## API key
Header (`X-API-Key`, `X-Auth-Token`) or a query param, via `http_request`.

## Brute force / credential spraying
No lockout? Spray with `http_fuzz` instead of one login at a time: put the marker
in the JSON/form password (`body:"{\"user\":\"admin\",\"pass\":\"FUZZ\"}"`) or in
a Basic-auth header; a password list as `payloads`; `match_status` (or
`match_regex` on a success token / the absence of the error message) to flag the
hit. Read the odd-one-out in the `length`/`status` column.
   Or pass `wordlist:"passwords"` (see `list_wordlists`) instead of an inline
   list — same summarized-hits output, no context bloat.

Rule: full header control + no CORS = `http_request`; reach for it whenever the
browser's implicit auth gets in the way.
