# SSRF, open redirect & web-service (.asmx/.svc) abuse

## SSRF
Server-side fetchers (`WebClient`/`HttpClient`/`WebRequest`, image proxies,
webhooks, PDF/preview generators, `Server.Transfer`). Find a `?url=`, `?src=`,
`?path=`, `?feed=`, `?target=` that the server retrieves.
- Probe cloud metadata & internal hosts with `http_request` (or `http_fuzz`
  over a host list): Azure IMDS
  `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  (needs header `Metadata:true`), AWS `http://169.254.169.254/latest/meta-data/`,
  `http://127.0.0.1:<admin-port>/`, `http://localhost/`. Confirm via reflected
  response or an OOB hit.
- Try alt schemes the .NET stack honours: `file://C:/inetpub/wwwroot/web.config`,
  `http://[::1]/`, decimal/octal IP encodings to dodge filters.

## Open redirect
`Response.Redirect(Request["returnUrl"])` and the Forms-auth `?ReturnUrl=` /
`?returnUrl=` parameter are classic. Test
`?ReturnUrl=https://evil.com`, `//evil.com`, `/\evil.com`,
`https:evil.com`, `https://target.tld@evil.com`. Read the 302 `Location` with
`http_request(..., follow_redirects:false)` then `http_flow` (or
`http_history(status:302)`). An off-host `Location` ⇒ open redirect (phishing /
auth-token theft).

## ASMX / WCF (.svc) / SOAP abuse
- GET `Service.asmx` lists operations; `Service.asmx?WSDL` dumps the contract;
  `Service.asmx?op=Method` shows a test form. `.svc` exposes WCF; `?wsdl` / `?xsd`
  enumerate it.
- Invoke an operation directly with `http_request`: `method:"POST"`,
  `headers:{"Content-Type":"text/xml; charset=utf-8","SOAPAction":"http://tempuri.org/Method"}`,
  and a SOAP-envelope `body`. Look for **unauthenticated** sensitive methods,
  SQLi / path traversal in the parameters (reuse skills 20/40), and verbose
  faults leaking stack traces.
- **XXE**: if the endpoint parses your XML, inject
  `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///C:/inetpub/wwwroot/web.config">]>` and
  reference `&e;` — read files or pivot to SSRF.

Evidence: IMDS/internal response, an off-host redirect `Location`, or a SOAP
method returning data / a file via XXE.
Remediation: allow-list outbound hosts & schemes (block link-local 169.254/127);
validate redirect targets against a same-host allow-list (`Url.IsLocalUrl`);
authenticate & authorize every web-service method; disable DTDs
(`XmlReaderSettings.DtdProcessing = Prohibit`).
