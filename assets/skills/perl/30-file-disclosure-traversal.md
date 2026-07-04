# File disclosure, traversal & source leak (Perl/CGI)

2-arg `open(FH, $path)` reads any file the daemon can; combined with traversal,
(old) NUL truncation, and blocklist gaps it leaks source, credentials, and
session data.

1. **Traversal**: `file=../../../../etc/passwd`, `page=../../etc/passwd`;
   URL-encode (`..%2f`), double-encode (`..%252f`), overlong UTF-8
   (`..%c0%ae%c0%ae/`), and the strip-once bypass `....//`. Sweep depths 3-10
   with `http_fuzz`, `match_regex:"root:.*:0:0:"`.
2. **NUL truncation** (old perl, <5.8 or unpatched): if the app appends an
   extension (`$file.".html"`), append `%00` — `../../etc/passwd%00`; combine
   with traversal AND the blocklist-bypass tricks from
   `20-command-injection.md` §4 (`na""tas`, `na?as`) when a keyword filter
   sits in front of the same `open()` sink.
3. **Source disclosure**: read the CGI's own source via the same `open` sink
   (`view=cgi-bin/login.cgi`), or fetch `/cgi-bin/login.cgi.bak` / `~` / `.swp`
   / `.orig` with `http_fuzz`. Perl source reveals DB creds (`DBI->connect`
   strings), `open`/`system` sinks, hard-coded secrets, and any `quote()` call
   worth revisiting in `40-sql-injection.md`.
4. **Session/config files**: `CGI::Session` defaults to file-backed storage —
   traverse to `/tmp/cgisess_<CGISESSID>` (the exact cookie value from
   `browser_get_cookies`) to read another user's serialized session data
   (`70-auth-session.md` territory once you have it). Also try `.htpasswd`,
   `httpd.conf`, `/proc/self/environ`.
5. **Absolute paths**: a leaked `... at /var/www/cgi-bin/app.pl line N` (from
   fingerprint) gives the on-disk root for `open`/traversal targets.
6. If the sink only opens and never prints, the read may still be provable —
   look for a length/status delta, an error message that echoes part of the
   path, or a follow-on feature (download/preview) that streams the opened
   handle back.

Evidence: contents of `/etc/passwd`, the script's own Perl source, or another
user's session file.
Remediation: 3-arg `open` with a path whitelist; reject `..`, `/`, and NUL; keep
data outside the web/cgi root; serve `.pl`/`.cgi` as executables only; store
sessions server-side with unpredictable, non-enumerable IDs.
