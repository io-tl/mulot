# Template injection & XSS (Go)

Go has TWO template packages — the bug is using the wrong one, or escaping out
of the safe one.

- **`html/template`** auto-escapes by output context (safe by default).
- **`text/template`** does NOT escape — if it renders an HTML response, every
  interpolated value is raw ⇒ XSS. Same for `fmt.Fprintf(w, "<b>%s</b>", input)`
  and any hand-built HTML string.
- **Escape bypass**: `template.HTML(x)`, `template.JS(x)`, `template.URL(x)`,
  `template.HTMLAttr(x)` mark user data as trusted, disabling escaping even under
  `html/template`. User input flowing into these ⇒ XSS.

1. Inventory inputs (`browser_get_form_fields`) and reflected params
   (`http_history`).
2. Find reflection fast with `http_fuzz`: marker on the value,
   `payloads:["xssPROBE1337"]`, `match_regex:"xssPROBE1337"`. A matched row =
   reflected; then read `http_flow_body` to see whether `< > & "` come back RAW
   (text/template or template.HTML ⇒ likely XSS) or ESCAPED (html/template
   working).
3. Confirm execution with `scan_xss` (it submits and verifies in the real DOM,
   never `alert()`). Fill other required fields with `browser_type` first, then
   `scan_xss` on the target field with context payloads via `payloads` (use
   `MARKER` for the proof token), e.g. attribute breakout
   `"><svg onload=window['MARKER']=1>`.
4. **SSTI** (rarer — user input as the template TEXT, not data): Go actions look
   like `{{.Field}}`. Inject `{{.}}` / `{{printf "%v" .}}`; if the response
   renders the context/dot instead of the literal text, the template is
   user-controlled — leaks the whole context struct (and any secret fields). Not
   Jinja-style RCE, but high-value disclosure. Test fields that clearly feed a
   templating feature (email/notification templates, themes, report layouts).

Evidence: payload + `executed:true` from `scan_xss`, or the raw `<svg>` echoed in
the body; for SSTI, the leaked context value.
Remediation: render HTML only with `html/template`; never feed user data to
`text/template` for HTML, nor wrap it in `template.HTML/JS/URL`; don't build HTML
with `fmt`/string concat; add a Content-Security-Policy.
