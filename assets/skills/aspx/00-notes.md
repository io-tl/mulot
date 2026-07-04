# ASP.NET / .NET — stack notes

- WebForms POSTbacks carry `__VIEWSTATE` / `__EVENTVALIDATION` /
  `__VIEWSTATEGENERATOR` in the body: capture the request with `http_history`,
  then replay/tamper it with `http_request from_flow` rather than rebuilding it.
- Decode/inspect `__VIEWSTATE` and do padding-oracle CBC byte math inside
  `browser_evaluate_js`.
