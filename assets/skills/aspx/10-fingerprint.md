# Fingerprint an ASP.NET / IIS stack

Confirm .NET, pick WebForms vs MVC vs Core, and surface exposed handlers.

Gather signals with `browser_navigate`, `browser_get_cookies`, `scan_passive`
(its `headers` section), `browser_get_form_fields`, and `http_request`:

- **Cookies**: `ASP.NET_SessionId` ⇒ classic ASP.NET. `.ASPXAUTH` ⇒ Forms auth.
  `__RequestVerificationToken` ⇒ MVC anti-CSRF. `.AspNetCore.*` /
  `.AspNetCore.Antiforgery.*` ⇒ ASP.NET Core. `ARRAffinity` ⇒ IIS ARR / Azure.
- **Headers**: `Server: Microsoft-IIS/x.y`, `X-AspNet-Version: 4.0.30319`
  (leaks framework version — finding), `X-AspNetMvc-Version` (MVC + version),
  `X-Powered-By: ASP.NET`. Each is an info leak — remove them.
- **Extensions/paths**: `.aspx`/`.ashx`/`.asmx`/`.axd`/`.svc`, `Default.aspx`,
  `/Account/Login`, `WebResource.axd`, `ScriptResource.axd`.
- **Hidden fields** (read with `browser_get_form_fields` or
  `browser_query_dom("input[type=hidden]")`): `__VIEWSTATE`,
  `__EVENTVALIDATION`, `__VIEWSTATEGENERATOR`, `__EVENTTARGET`,
  `__EVENTARGUMENT` ⇒ WebForms. Note them for the viewstate/postback skills.
- **Error pages**: the "Yellow Screen of Death" with a stack trace and
  `[SqlException]` / file paths means `<customErrors mode="Off">` (info leak).
  Trigger one (bad param) and read it with `http_flow_body` on the 500.
- **Forced-browse in ONE `http_fuzz`** (`url:"http://host/FUZZ"`,
  `match_status:200`): `payloads:["Trace.axd","elmah.axd","web.config",
  "web.config.bak","WebResource.axd","ScriptResource.axd","glimpse.axd",
  "App_Data/","bin/","Service.asmx","api/"]`. Each 200 / `matched` is a finding
  (Trace.axd & elmah.axd leak requests; web.config leaks `connectionStrings` &
  `machineKey`).

Record: .NET version, WebForms vs MVC vs Core, IIS version, and every exposed
handler/config file.

Evidence: the version headers + each exposed `.axd`/config response.
Remediation: remove `X-AspNet*`/`X-Powered-By` headers, `<customErrors
mode="RemoteOnly">`, disable `Trace.axd`/ELMAH remote access, deny `web.config`.
