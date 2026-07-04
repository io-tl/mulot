# SQL injection (Go)

Go's `database/sql` is safe WHEN queries are parameterized
(`db.Query("...WHERE id=?", id)` / `$1`). The bug is string-built SQL —
`fmt.Sprintf("...WHERE id=%s", id)` or `+` concatenation. Test every
query/JSON/form parameter and any `?id=` / path id.

1. **Find inputs**: `browser_get_form_fields`, params in `http_history`, JSON
   bodies from `http_flow_body`.
   Prioritize `?sort=`, `?order=`, `?order_by=`, `?group=`, `?filter=` params
   — GORM's `.Order()/.Group()/.Having()` and `.Raw()` take raw SQL fragments
   even though `.Where()` is parameterized, making sort/filter params the
   most common real-world Go+GORM injection point.
2. **Error-based**: inject `'` and submit (`http_request`, or `browser_type` +
   `browser_click` + `browser_wait_for`). A raw driver error in the response body
   confirms injectability:
   `pq: ...` (lib/pq, Postgres — legacy) or `ERROR: syntax error at or near
   ... (SQLSTATE 42601)` (pgx/pgxpool, now the default Postgres driver incl.
   under GORM's postgres dialect), `Error 1064 ... MySQL` (go-sql-driver),
   `sqlite3: SQL logic error`, `near "...": syntax error`, `ORA-`, `mssql:`.
   Sweep every engine in one `http_fuzz` pass:
   `match_regex:"SQLSTATE|syntax error at or near|pq: |Error 1064|sqlite3: SQL logic error|ORA-|mssql:"`.
3. **Boolean-blind**: compare `id=1 AND 1=1` vs `id=1 AND 1=2` (and quoted
   variants `1' AND '1'='1`). A differential `length`/status ⇒ blind SQLi. Sweep
   both with one `http_fuzz` (marker on the value) and read the length deltas.
4. **UNION**: find the column count with `' ORDER BY n-- ` — `http_fuzz` marker
   on `ORDER BY FUZZ-- `, `payloads:["1","2",...,"20"]`. Then `' UNION SELECT
   ...-- ` to dump. Postgres: `::text` casts + `string_agg(col,',')`,
   `information_schema`; MySQL: `group_concat(...)`.
5. Prefer `http_request from_flow` for single tampered requests (carries the
   session); `http_fuzz` with `match_regex` on the driver-error strings above to
   flag injectable rows across many payloads at once.

Evidence: the injected request + the driver error or the dumped rows.
Remediation: always parameterize (`?` / `$1` placeholders via `QueryContext`);
never `fmt.Sprintf`/`+` user input into SQL; use `sqlx` or an ORM with bound
args. Identifiers that must be dynamic go through a strict allowlist, not concat.
