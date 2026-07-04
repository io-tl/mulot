# Fingerprint a Perl / CGI stack

1. **Extensions/paths**: `.pl`, `.cgi`, `.pm` URLs; anything under `/cgi-bin/`.
   `http_fuzz` forced-browse `http://host/cgi-bin/FUZZ` with common names
   (`test.cgi`, `printenv.pl`, `test-cgi`, `search.cgi`, `admin.cgi`,
   `formmail.pl`, `guestbook.cgi`, `upload.cgi`, `index.pl`), `match_status:200`.
2. **Server header** (`http_flow` / `scan_passive`): `Server: Apache ...
   mod_perl/2.x`, `Perl/v5.x.y`; `X-Powered-By` rarely present. mod_perl means
   the interpreter is LONG-LIVED across requests — package globals can leak
   state between users (a lead for IDOR/race testing, not just RCE).
3. **Cookies** (`browser_get_cookies`): `CGISESSID` (CGI::Session, file-backed
   under `/tmp/cgisess_*` by default — a traversal target, see
   `30-file-disclosure-traversal.md`), `SESSION`, custom session names.
4. **Error pages**: "Software error", CGI::Carp dumps, Perl `die` messages
   (`... at /path/script.pl line 42.`, `Can't locate Foo.pm in @INC`), taint-mode
   errors (`Insecure dependency in ... while running with -T switch` — note
   when `-T` IS present, since it narrows viable sinks), 500s that leak the
   script's absolute path — read with `http_flow_body`.
5. **Upload/param-pollution surface**: `browser_get_form_fields` on every form;
   flag any `<form enctype="multipart/form-data">` containing a file `<input>`
   PLUS another field sharing a name with the file field, or a dropdown/
   `<select>` whose value feeds a file-loading script (`action=`, `file=`,
   `page=`, `view=`) — classic setup for `CGI->param()` context confusion
   (`25-cgi-param-pollution.md`).
6. **DB backend**: DBI error strings or a login form ⇒ note `DBD::mysql`,
   `DBD::Pg`, `DBD::SQLite`, `DBD::Oracle` from any leaked error (see
   `40-sql-injection.md`).
7. **Known apps**: Bugzilla, AWStats (`awstats.pl`), Webmin, nagios `.cgi`, old
   guestbooks / FormMail / CGI::Session demo apps.

Record: Perl version, web server + mod_perl vs plain CGI, the `/cgi-bin/` base,
any leaked absolute script path (drives traversal / source disclosure), and
every form/param flagged in step 5 — they are your priority targets.
