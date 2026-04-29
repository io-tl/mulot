# SQL injection (PHP)

PHP + MySQL apps are classic SQLi targets. Test every GET/POST parameter and
form field.

1. **Find inputs**: `browser_get_form_fields`, plus parameters seen in
   `http_history`.
2. **Error-based**: inject a single quote `'` and submit (`browser_type` +
   `browser_click` + `browser_wait_for`, or `http_request`). Look in the
   response for SQL errors: `You have an error in your SQL syntax`,
   `mysql_fetch`, `PDOException`, `Warning: mysqli`. An error ⇒ injectable.
3. **Boolean-blind**: compare `id=1' AND '1'='1` (normal) vs `id=1' AND '1'='2`
   (different/empty). A differential `length`/status ⇒ blind SQLi. Sweep both with
   one `http_fuzz` (marker on the `id` value, the two payloads) and read the
   length deltas.
4. **UNION extraction**: find the column count with `' ORDER BY n-- -`, then
   `1' UNION SELECT user,password FROM users-- -`. Read the dumped rows from the
   response body. `http_fuzz` with `marker=FUZZ` on `ORDER BY FUZZ-- -` and
   payloads `1..20` finds the column count in one call.
5. Prefer `http_request` for single tampered requests (it carries the session;
   use `from_flow` to re-issue a captured request with a tampered parameter), and
   `http_fuzz` to sweep many payloads at once (`match_regex` on the SQL-error
   strings above flags injectable rows automatically).

Evidence: the injected request + the SQL error or dumped data.
Remediation: parameterized queries / PDO prepared statements; never concatenate
user input into SQL.
