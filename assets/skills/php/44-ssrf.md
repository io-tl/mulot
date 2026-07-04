# SSRF (PHP)

Any param the server fetches server-side (`?url=`, `?image=`, webhook, avatar/
thumbnail proxy using `curl_exec`, `file_get_contents`, `fopen`, `Guzzle`,
`SimpleXMLElement` with a remote URL). Point it inward via `http_request`:
`http://169.254.169.254/latest/meta-data/` (cloud creds), `http://127.0.0.1:<port>`,
`http://localhost`, `file:///etc/passwd`, `gopher://127.0.0.1:<port>/...`
(if `allow_url_fopen` covers gopher). Read the fetched body back in the
response; blind SSRF ⇒ timing (`elapsedMs`). Sweep hosts/ports/schemes with one
`http_fuzz`.

PHP-specific wrappers widen the reach: `php://filter/convert.base64-encode/
resource=...` leaks local source when the SSRF feeds an `include`; `dict://` /
`gopher://` talk to internal Redis/FastCGI/SMTP when `allow_url_fopen`/curl
allows the scheme; `expect://` is RCE where the extension is loaded. Decimal/
octal/IPv6 host encodings (`http://2130706433/`, `http://[::1]/`) dodge naive
`127.0.0.1`/`localhost` string filters.

For CORS misconfiguration on the same target, load the `cors-redirect`
capability (`load_skill(["cors-redirect"])`).

Evidence: the internal/cloud response body, or the local file/source dumped
through a wrapper.
Remediation: allow-list outbound hosts + block link-local/loopback and
non-http(s) schemes; disable `allow_url_fopen`/`allow_url_include`; never pass
user input to a URL-fetching call.
