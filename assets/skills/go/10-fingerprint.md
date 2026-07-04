# Fingerprint a Go stack

Go ships few banners — confirm Go and the framework mostly from negatives and
default error text. Gather with `browser_navigate`, `browser_get_cookies`,
`scan_passive` (its `headers` section), `http_request`, `http_flow`.

- **Headers**: often NO `X-Powered-By`. `Server:` may be absent, or a reverse
  proxy only. The absence of PHP/ASP cookies plus a bare/missing `Server` is
  itself a Go tell. Echo may emit `Server: Echo`; Fiber sets a `Server` header
  only if configured.
- **Cookies**: gorilla/sessions ⇒ a `session` cookie. Fiber CSRF middleware ⇒
  `csrf_` / `__Host-*`. JWT often lives in an `Authorization: Bearer` header or a
  `token`/`jwt` cookie (three base64url segments — skill: auth-jwt-idor).
- **Default 404 body** (hit a random path with `http_request`, read the body):
  net/http `ServeMux` ⇒ plaintext `404 page not found`; Gin ⇒ `404 page not
  found` too; Echo ⇒ `{"message":"Not Found"}`; Fiber ⇒ `Cannot GET /path`;
  Chi ⇒ a bare 404. `405` text `Method Not Allowed` likewise discriminates.
- **Panic / stack traces**: a 500 body with `goroutine NN [running]:`, paths like
  `/usr/local/go/src/`, `runtime.gopanic`, or Gin's `[Recovery] ... panic
  recovered` is Go AND an info leak (source paths, struct field names). Trigger
  with malformed input (wrong type in a JSON/query param) and read via
  `http_flow_body`.
- **Ops/debug surface** (big Go tells): `/debug/pprof/`, `/debug/vars` (expvar),
  `/metrics` (Prometheus), `/healthz`, `/readyz`. Sweep in ONE `http_fuzz`
  forced-browse: `url:"http://host/FUZZ"`, `match_status:200`,
  `payloads:["debug/pprof/","debug/vars","metrics","healthz","readyz","api/",
  "api/v1/","version","build"]`. Each 200 is a lead → skill: debug-endpoints.

Record: framework guess, Go version if a stack trace / `/debug/vars` / `go_info`
leaks it, and every exposed ops/debug path (each a finding).
