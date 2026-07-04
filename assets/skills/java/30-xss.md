# Cross-site scripting (Java)

JSP `<%= request.getParameter() %>`, Spring MVC model echoes, Thymeleaf
`th:utext` (unescaped), and JSF can all reflect input unescaped.

1. Inventory inputs (`browser_get_form_fields`) and reflected params
   (`http_history`).
2. Find reflection fast with `http_fuzz`: marker on the param value, a unique probe
   `payloads:["xssPROBE1337"]`, `match_regex:"xssPROBE1337"`. A matched row = input
   reflected — then confirm execution (HTTP reflection alone isn't proof).
3. `scan_xss` on each reflected input — it SUBMITS the form and confirms execution
   in the real browser DOM via a non-blocking marker (never `alert()`).
   - Fill OTHER required fields with `browser_type` FIRST, then `scan_xss` with a
     single payload on the target field.
   - Context payloads via `payloads` (use `MARKER` for the proof token): attribute
     breakout `"><svg onload=window['MARKER']=1>`; pages rendered by Thymeleaf
     `th:utext` reflect into HTML text.
4. **Reflected** (echoed now), **Stored** (persists, fires later), **DOM** (fires
   without submit) — `scan_xss` detects all three. Inspect the output context with
   `http_flow_body` to pick the right breakout.

Evidence: the payload + `executed:true` from `scan_xss` (with context).
Remediation: contextual output encoding (JSP `<c:out>` / `fn:escapeXml`, OWASP Java
Encoder), Thymeleaf `th:text` not `th:utext`, and a Content-Security-Policy.
