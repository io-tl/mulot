# Auth & session (Perl/CGI)

1. **Session IDs**: `CGISESSID` / custom cookies (CGI::Session) — check for
   predictable/sequential IDs, missing `HttpOnly`/`Secure`, and fixation (does
   the ID rotate after login? compare `browser_get_cookies` before and after
   `scan_login`). CGI::Session defaults to file-backed storage under
   `/tmp/cgisess_<id>` — if you have ANY file-read primitive
   (`30-file-disclosure-traversal.md`), read another session file directly
   instead of guessing the ID.
2. **Login**: `scan_login` with a `success_indicator`; when there's no
   lockout, spray default/weak creds with `http_fuzz` (`match_status` or a
   success/failure `match_regex`). Also try SQL-tautology creds
   (`admin'-- -`) — see `40-sql-injection.md` §6.
3. **IDOR / access control**: capture an authenticated request
   (`http_history`), then `http_request from_flow` with `use_session:false` or
   another user's `cookies`; enumerate numeric ids with `http_fuzz`. Also test
   the `param()` duplication trick (`25-cgi-param-pollution.md` §5) on any
   boolean/id-based gate.
4. **Basic auth**: `/cgi-bin/` is often behind Apache Basic auth — send
   `Authorization: Basic <base64(user:pass)>` via `http_request`; brute-force
   with `http_fuzz` (marker in the header value, one base64 blob per
   credential pair, `match_status:200` vs `401`).
5. **CSRF**: CGI scripts rarely emit a token — check whether a state-changing
   GET/POST works with `use_session:true` but no Origin/Referer/token; if so,
   any authenticated GET is a CSRF candidate.

Evidence: the request/response showing access without proper authorization, or
another user's session file contents.
Remediation: use a vetted session module with CSPRNG IDs, rotate on login, set
HttpOnly+Secure, move session storage server-side outside the web root;
enforce per-object authorization server-side; add CSRF tokens to state-changing
requests.
