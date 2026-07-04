# Perl / CGI — stack notes

Classic Perl CGI is uniquely RCE-prone — the language's I/O and string `eval`
turn ordinary sinks into command execution:
- 2-argument `open(FH, $x)` is magic: a trailing `|` runs `$x` as a command, a
  leading `>`/`>>` writes, `<` reads, and `../`/absolute paths read any file. A
  filename like `"id|"` or `"|id"` → RCE; `"/etc/passwd"` → file read.
- Contact/feedback forms often pipe to sendmail (`open(MAIL,"|/usr/sbin/sendmail
  -t")`) — a newline in a field injects extra mail headers (Bcc/To).
- Old perls truncate on a NUL byte: `file=../../etc/passwd%00` defeats a
  `".$ext"` suffix.
- No taint mode (`-T`) means user input flows straight into these sinks.
- `CGI->param('x')` context confusion: duplicate the same field name and the
  value picked differs by scalar vs list context — enough to disable SQL
  escaping or smuggle "ARGV" into a magic-open sink; see
  `25-cgi-param-pollution.md`.
- Under mod_perl the interpreter persists across requests: a script using
  package/global variables (not `my`) instead of lexicals can leak one user's
  data/session into another's response — worth an IDOR-by-race check.

Sweep with `http_fuzz`; decode/encode payloads with `browser_evaluate_js`.
