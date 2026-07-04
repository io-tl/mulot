# Cross-site scripting (Node)

Server-rendered (EJS/Pug/Handlebars unescaped output) and client-rendered
(React/Vue/Next) Node apps both XSS. Test every input reflected into HTML or DOM.

1. Inventory inputs (`browser_get_form_fields`) and reflected params / JSON fields
   (`http_history`).
2. Find reflection points fast with `http_fuzz`: marker on the value, a unique
   probe `payloads:["xssPROBE1337"]`, `match_regex:"xssPROBE1337"`. A `matched`
   row means it is reflected — then confirm execution (reflection ≠ proof).
3. `scan_xss` on each reflected input — it SUBMITS and confirms execution in the
   real DOM via a non-blocking marker (never `alert()`). Fill other required
   fields with `browser_type` first, then `scan_xss` on the target field.
   Context payloads via `payloads` (use `MARKER` for the proof token):
   attribute breakout `"><svg onload=window['MARKER']=1>`, JS-string
   `';window['MARKER']=1;//`.
4. **Node-specific sinks**:
   - Unescaped template tags: EJS `<%- x %>`, Handlebars `{{{x}}}`,
     Pug `!{x}` / `td!= x` — raw HTML, no escaping.
   - React `dangerouslySetInnerHTML={{__html:x}}`, or a user-controlled
     `href`/`src` allowing a `javascript:` URL.
   - DOM XSS in bundled JS: `innerHTML` / `document.write` / `eval` of
     `location` / `postMessage` data — `scan_passive` flags these sinks.
5. **Stored**: persists and fires on a later page (comments, profile, filenames);
   `scan_xss` detects reflected, stored and DOM.

Evidence: the payload + `executed:true` from `scan_xss` (with context).
Remediation: contextual auto-escaping (default template tags, never `<%-` /
`{{{` / `!{`), avoid `dangerouslySetInnerHTML`, a strict Content-Security-Policy,
and sanitize stored HTML (DOMPurify).
