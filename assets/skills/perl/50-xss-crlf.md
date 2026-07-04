# Reflected/stored XSS & CRLF / header injection (Perl/CGI)

CGI scripts frequently `print` user input straight into the body or into HTTP
headers built by hand — no framework auto-escaping to rely on.

1. **Reflected XSS**: find a reflected param with `http_fuzz`
   (`match_regex:"xssPROBE1337"`), then confirm execution with `scan_xss` (it
   submits the form and detects DOM execution). Try `<script>alert(1)</script>`
   first, then `"><svg onload=alert(1)>` / `<img src=x onerror=alert(1)>` if
   `<script>` is stripped — Perl forms rarely HTML-escape by default.
2. **Stored XSS**: guestbooks/forums/comment CGIs (classic Perl app genre)
   persist input verbatim — submit a unique marker
   (`<script>alert('xssSTOREDmarker')</script>`), then `browser_navigate` to
   every page that renders it (including any admin/moderation view) and check
   with `scan_xss`/`browser_get_console`.
3. **CRLF / response splitting**: scripts that emit `print "Location: $url\n\n"`
   or `print "Set-Cookie: ...$x...\n"` let you inject headers. Put `%0d%0a`
   (also try lone `%0a`, lone `%0d`, and double-encoded `%250d%250a` if the
   first is stripped) in the param — `?url=%0d%0aSet-Cookie:+sessid=attacker`,
   or `?url=%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(1)</script>` to
   smuggle a full body. Send with `http_request` (`follow_redirects:false`)
   and read the raw headers via `http_flow`.
4. Confirm a cookie/header injection actually lands by re-issuing the request
   and checking `browser_get_cookies` / `http_flow` for the smuggled value.

Evidence: payload executes (`scan_xss` → `executed:true`) / an injected header
or cookie appears in the response.
Remediation: HTML-escape output (`HTML::Entities::encode_entities`); strip CR/LF
from any value placed in a header; emit headers via `CGI`/a framework, not
`print`; set a CSP as defense in depth.
