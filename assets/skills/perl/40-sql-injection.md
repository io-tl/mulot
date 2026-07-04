# SQL injection (Perl DBI)

Perl DBI is safe with placeholders (`?`) but apps often interpolate:
`$dbh->do("SELECT * FROM users WHERE name='$n'")`, or call `$dbh->quote($n)`
without forcing scalar context (see below) — test every DBI-backed input.

1. **Error-based**: inject `'` and look for DBI errors — `DBD::mysql::st
   execute failed`, `DBD::Pg::st execute failed`, `DBD::SQLite::db prepare
   failed`, `syntax error`, `unterminated quoted string`. The DBD name in the
   error tells you the dialect for the rest of this sweep.
2. **Boolean-blind**: `' AND '1'='1` vs `' AND '1'='2`; sweep both in one
   `http_fuzz` (marker on the value) and read the `length` delta.
3. **UNION**: `' ORDER BY n-- -` swept `n=1..20` with `http_fuzz` for the
   column count (watch for the error to disappear), then
   `' UNION SELECT username,password FROM users-- -`.
4. **Time-based blind** (when errors/length are suppressed): MySQL
   `' OR SLEEP(5)-- -`, PostgreSQL `'; SELECT pg_sleep(5)-- -`, SQLite has no
   sleep — fall back to a heavy `' OR (SELECT COUNT(*) FROM sqlite_master,
   sqlite_master, sqlite_master)-- -`. Compare `timeMs` across `http_fuzz` rows.
5. **`quote()` type-confusion (natas30 class)**: if the code calls
   `$dbh->quote($cgi->param('username'))` WITHOUT `scalar(...)`, duplicating
   the `username` field lets you pass `quote()` a 2nd positional argument —
   its optional SQL-type parameter. A bare integer there (try `1`/`2`/`4`)
   disables escaping outright. Send an ordinary urlencoded POST with the
   field twice: `username=' OR '1'='1&username=2&password=x` via
   `http_request`. See `25-cgi-param-pollution.md` for the underlying
   primitive and more sinks.
6. **Auth bypass**: `admin'-- -` / `' OR '1'='1'-- -` in a login form's
   username, blank password.
7. Replay a captured request with a tampered param via `http_request
   from_flow`.

Evidence: the DBI error string, a length/time delta, or dumped rows.
Remediation: always use placeholders — `$dbh->prepare("... WHERE name=?")` then
`execute($n)`; never interpolate user input into SQL; if `quote()` is
unavoidable, call it as `$dbh->quote(scalar($cgi->param($n)))` so a duplicated
parameter can't smuggle its type argument.
