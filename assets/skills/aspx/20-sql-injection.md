# SQL injection (ASP.NET + SQL Server)

Classic `SqlCommand("...'" + input + "'...")` string concatenation over ADO.NET.
Test every GET/POST parameter, route segment, and form field.

1. **Find inputs**: `browser_get_form_fields`, route params, and parameters seen
   in `http_history`. WebForms controls submit via a postback — capture the POST
   with `http_history` so you can replay it (the `__VIEWSTATE` /
   `__EVENTVALIDATION` must ride along; tamper with `http_request from_flow`).
2. **Error-based**: inject a single quote `'`. Look in the response for SQL
   Server errors: `System.Data.SqlClient.SqlException`, `Unclosed quotation
   mark after the character string`, `Incorrect syntax near`, `Conversion
   failed when converting`, `Microsoft OLE DB Provider`. An error ⇒ injectable
   (and a verbose YSOD if `customErrors` is off).
3. **Boolean-blind**: compare `id=1 AND 1=1` (normal) vs `id=1 AND 1=2`
   (different/empty). Quote-wrapped: `' AND '1'='1` vs `' AND '1'='2`. Sweep
   both with one `http_fuzz` (marker on the value) and read the `length` deltas.
4. **Time-based**: `1; WAITFOR DELAY '0:0:5'--` or `' WAITFOR DELAY '0:0:5'--`.
   A ~5 s response delta confirms blind SQLi. SQL Server allows stacked queries
   with `;`.
5. **UNION extraction**: column count with `' ORDER BY n-- ` (sweep `1..20` via
   `http_fuzz`), then `' UNION SELECT name,master.dbo.fn_varbintohexstr(...) ...`.
   Enumerate schema via `sys.tables` / `INFORMATION_SCHEMA.COLUMNS`; read SQL
   Server version with `@@version`.
6. Prefer `http_request from_flow` for single tampered postbacks; `http_fuzz`
   with `match_regex` on the SQL-error strings above to flag injectable rows.

Evidence: the injected request + the SqlException text or dumped data.
Remediation: parameterized `SqlCommand` with `SqlParameter` (or EF/Dapper
parameters); never concatenate input into SQL; run the app under a
least-privilege DB account.
