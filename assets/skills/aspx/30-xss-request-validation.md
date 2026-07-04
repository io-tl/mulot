# XSS & ASP.NET request-validation bypass

ASP.NET ships **request validation**: a payload like `<script>` throws
`HttpRequestValidationException` — "A potentially dangerous Request.Form value
was detected" (HTTP 500). So first find where validation is OFF or doesn't apply.

1. Inventory inputs (`browser_get_form_fields`) and reflected parameters
   (`http_history`). Watch for `__VIEWSTATE`-driven reflections too.
2. Find reflection fast with `http_fuzz`: marker on the param value, a unique
   probe `payloads:["xssPROBE1337"]`, `match_regex:"xssPROBE1337"`. A `matched`
   row = reflected — then confirm execution with `scan_xss`.
3. **Validation-bypass surfaces** (no `HttpRequestValidationException` there):
   - `.ashx` generic handlers and Web API / JSON endpoints (no request
     validation).
   - MVC actions with `[ValidateInput(false)]` or model props `[AllowHtml]`.
   - Pages with `validateRequest="false"` / `requestValidationMode="2.0"`.
   - **Attribute / JS-string context**: validation mainly blocks `<x` and `&#`,
     not breaking out of an existing attribute. Try
     `" autofocus onfocus="window['MARKER']=1`, `'-window['MARKER']-'` inside a
     `<script>` string, or `javascript:` in an `href`.
4. Confirm with `scan_xss` (it SUBMITS and checks execution in the real DOM via a
   non-blocking marker, never `alert()`). Fill other required fields with
   `browser_type` first, then `scan_xss` with one payload on the target field.
   Use `MARKER` for the proof token.
5. **Reflected** / **Stored** (persists, fires later) / **DOM** — `scan_xss`
   detects all three. Inspect the output context with `http_flow_body` to pick
   the breakout.

Evidence: the payload + `executed:true` from `scan_xss` (with context).
Remediation: keep request validation ON, encode on output
(`Html.Encode`/Razor `@` auto-encodes, `AntiXssEncoder`), avoid
`[AllowHtml]`/`validateRequest=false`, add a Content-Security-Policy.
