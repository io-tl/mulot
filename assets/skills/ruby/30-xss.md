# Cross-site scripting (Ruby / Rails)

Rails (ERB) auto-escapes `<%= %>` by default, so XSS lives where that escaping is
bypassed. Sinatra/ERB without `escape_html` and Haml/Slim raw output are exposed
by default.

1. Inventory inputs (`browser_get_form_fields`) and reflected params
   (`http_history`).
2. **Suspect sinks** (escaping bypassed): `raw(x)`, `<%== x %>`, `x.html_safe`,
   `sanitize` with a permissive allowlist, `content_tag`/`tag` with raw attrs,
   `link_to name, "javascript:..."`, and any value rendered into an `href`/`src`
   or inside `<script>`. JSON-in-script via `<%= raw j(...) %>` mistakes.
   Turbo Stream broadcasts (`turbo_stream.append/replace/update` rendering a
   partial with raw/html_safe user content, pushed over ActionCable) — fires in
   every subscribed client's DOM, not just the submitter's; a higher-impact
   stored-XSS variant specific to the Hotwire default stack.
3. Find reflection fast with `http_fuzz`: marker on the param value, a unique
   probe `payloads:["xssPROBE1337"]`, `match_regex:"xssPROBE1337"`. A `matched`
   row means it is reflected — then confirm execution with `scan_xss` (HTTP
   reflection alone isn't proof; auto-escaping may neutralise it).
4. Use `scan_xss` on each reflected input — it SUBMITS the form and confirms
   execution in the real browser DOM via a non-blocking marker (never `alert()`).
   - Fill other required fields with `browser_type` FIRST, then `scan_xss` the
     target field.
   - Context payloads via `payloads` (use `MARKER` for the proof token), e.g.
     attribute breakout `"><svg onload=window['MARKER']=1>`, or a
     `javascript:`-scheme URL if the value lands in an `href`.
5. **Reflected** (echoed in the response), **Stored** (persists, fires on a later
   page — e.g. a comment/profile field rendered with `raw`), **DOM** (fires on
   input without submit). `scan_xss` detects all three. Inspect output context
   with `http_flow_body` to pick the breakout.

Evidence: the payload + `executed:true` from `scan_xss` (with context).
Remediation: rely on ERB auto-escaping — drop `raw`/`html_safe`/`<%==` on user
data; use `sanitize` with a strict allowlist; never build `href`/`src` from raw
input; add a Content-Security-Policy via `config.content_security_policy`.
