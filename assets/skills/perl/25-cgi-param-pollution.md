# CGI.pm param()/upload() context confusion (Perl/CGI)

`CGI->param('x')` behaves differently depending on context and how many values
were submitted for `x` — apps that don't force `scalar(...)` leak this into
sinks. This is the exact bug class behind two unresolved OverTheWire Natas
findings (31/32, RCE) and one resolved one (30, SQLi) — arm it fully.

1. **The primitive**: submit the SAME field name twice (or an upload field
   plus a plain field of the same name). `param('x')` in LIST context returns
   ALL values in submission order; in SCALAR context it returns only the
   FIRST. A sink that calls `param()` directly as a function argument (not
   pre-assigned with `scalar`) silently receives list context — so the
   position of your extra value in the raw body decides what the sink sees.
2. **Build it with `http_request`, not the browser**: `browser_upload_file`
   drives one DOM `<input type="file">` and can't express a duplicate/reordered
   field. Hand-craft the multipart body instead — set
   `headers:{"Content-Type":"multipart/form-data; boundary=B"}` and a `body`
   with literal `\r\n` line endings:
   ```
   --B\r\nContent-Disposition: form-data; name="file"\r\n\r\nARGV\r\n
   --B\r\nContent-Disposition: form-data; name="file"; filename="x.csv"\r\nContent-Type: text/plain\r\n\r\n1,2,3\r\n--B--\r\n
   ```
   Put your controlled value in the part whose position matches the context
   the sink uses (first part for scalar-context sinks).
3. **Escalate to RCE (open/diamond on ARGV)**: if the sink is
   `while (<$file>)` after `my $file=$cgi->param('file')`, the payload above
   turns `$file` into the string `"ARGV"` — Perl's `<$file>` then reads
   whatever is in `@ARGV`. CGI.pm populates `@ARGV` from the URL's query
   string when it contains NO `=` (legacy ISINDEX "keywords" parsing): send
   `POST /script.cgi?|id|` or `POST /script.cgi?cat%20/etc/passwd|` — the
   trailing `|` makes the 2-arg `open` inside the ARGV loop pipe/exec. See
   `20-command-injection.md` §3 for metacharacter/blocklist follow-ups.
4. **Escalate to SQLi (`DBI->quote()` type confusion)**: if the sink is
   `$dbh->quote($cgi->param('username'))` (no `scalar`), `quote()` receives
   your two submitted values positionally as `($string, $type)`. `quote()`'s
   optional 2nd arg is a DBI SQL type; passing a bare integer for it (try
   `1`, `2`, `4`) makes `quote()` skip escaping entirely. Submit the field
   twice in an ordinary urlencoded POST body via `http_request`:
   `username=' OR '1'='1&username=2&password=x`. See `40-sql-injection.md`
   §5 for the injection payloads to put in the first slot.
5. **Also test for auth/ID-check bypass**: any `if (grep {$_ eq
   $cgi->param('id')} @allowed)` or boolean gate reading `param()` directly
   (not `scalar`) can be smuggled the same way — duplicate the field so the
   list contains both a benign and a forbidden value.
6. Confirm every hit with proof (command output / DBI error text / dumped
   rows / access granted) before reporting — a 200 alone is not proof.

Evidence: command output, DBI error/dumped rows, or access granted with a
smuggled id.
Remediation: always call `scalar($cgi->param($x))` (or `$cgi->multi_param`
only when a list is intentional); never pass `param()`'s return directly into
`open`/`quote`/a boolean check; reject query strings without `=` (disable
ISINDEX/keywords compatibility) at the CGI dispatcher.
