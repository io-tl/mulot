# Cross-site scripting (PHP)

1. Inventory inputs (`browser_get_form_fields`) and reflected parameters
   (`http_history`).
2. Find reflection points fast with `http_fuzz`: marker on the param value, a
   unique probe like `payloads:["xssPROBE1337"]` (or a few breakout strings),
   `match_regex:"xssPROBE1337"`. A `matched` row means the input is reflected —
   then confirm execution with `scan_xss` (HTTP reflection alone isn't proof).
3. Use `scan_xss` on each reflected input — it SUBMITS the form and confirms
   execution in the real browser DOM via a non-blocking marker (never `alert()`).
   - If the form has OTHER required fields (e.g. a guestbook name), fill them
     with `browser_type` FIRST, then call `scan_xss` with a single
     payload on the target field.
   - Supply context-specific payloads via `payloads` (use `MARKER` for the proof
     token), e.g. attribute breakout `"><svg onload=window['MARKER']=1>`.
4. **Reflected**: payload echoed in the immediate response. **Stored**: persists
   and fires on a later page. **DOM**: fires on input without submit.
   `scan_xss` detects all three.
5. Inspect the output context with `http_flow_body` to pick the right
   breakout (HTML text, attribute, inside `<script>`, JS string).

Evidence: the payload + `executed:true` from `scan_xss` (with context).
Remediation: contextual output encoding (`htmlspecialchars($x, ENT_QUOTES)`),
a Content-Security-Policy, and never echoing raw input.
