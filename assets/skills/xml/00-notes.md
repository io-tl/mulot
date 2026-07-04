# XML attack surface — notes

Load this playbook (`load_skill(["xml"])`) whenever the target parses XML you can
influence, WHATEVER the backend stack. XML is a capability, not a stack: it rides
inside PHP, Java, .NET, Python and Node apps alike, so load it *in addition* to the
detected stack. Signals: `Content-Type: application/xml`/`text/xml`, SOAP
(`SOAPAction` header, `<soap:Envelope>`), SAML SSO (`SAMLResponse`/`SAMLRequest`
base64 params, `/saml/`, `/sso/`, `/acs`), XML-RPC (`/xmlrpc.php`, `<methodCall>`),
RSS/Atom/feed or sitemap import, and uploads that are XML under the hood (`.svg`,
`.xml`, `.docx`/`.xlsx`/`.pptx` = OOXML zips, `.rss`).

## Vuln classes covered
- XXE — in-band file read + SSRF (`20`), blind / OOB / error-based (`30`).
- XPath injection — auth bypass + direct/blind data extraction (`40`, `45`).
- XSLT injection — file read / SSRF / RCE via extension functions (`50`).
- SAML — signature wrapping / stripping / comment truncation + assertion XXE (`60`).
- SOAP & XML-RPC — SOAPAction/WS-Security abuse, pingback SSRF, multicall
  brute-force bypass (`65`).
- Parser & WAF bypasses when a naive payload is filtered or hardening bites (`70`).

## Parser-specific reality (why a textbook XXE sometimes "fails")
- **PHP (libxml ≥ 2.9)**: external-entity loading is OFF by default. Vulnerable
  only if the app calls `libxml_disable_entity_loader(false)` or passes
  `LIBXML_NOENT`/`LIBXML_DTDLOAD`. When it IS on, prefer `php://filter/...base64`
  to read source without breaking the parse on `<` chars.
- **Java** (`DocumentBuilderFactory`, SAX, dom4j, JAXB, `XMLStreamReader`):
  vulnerable unless explicitly hardened; often allows directory listing and extra
  schemes (`jar:`, `netdoc:`, `ftp:`). See the `java` stack's XXE notes too.
- **.NET**: `XmlDocument`/`XmlTextReader` on old frameworks resolve entities via
  `XmlResolver`; `XmlReaderSettings.DtdProcessing=Parse` re-enables it.
- **Python**: `lxml` blocks network entities by default but `etree`/`xml.sax`/
  `xml.dom.minidom` (libxml2/expat) can still read local files; `defusedxml` ⇒
  give up on XXE and pivot.

## Rules of engagement
- **Do NOT run denial-of-service as "proof"** — no billion-laughs, no quadratic
  blowup, no 1e9-entity bomb against a live target; it can take the app down. To
  show the parser expands entities, use ONE tiny 2-level entity and confirm the
  expansion in the response.
- **OOB needs a listener YOU control** (`http://<oob>/`). mulot does not host one.
  With no collaborator, confirm in-band instead: error-based exfil that returns the
  data in the HTTP response, or an internal SSRF fetch you can read back — see `30`
  for the exact preconditions of each.
- Send payloads with `http_request` and the exact `Content-Type` the endpoint
  expects; capture the response body from the journal (`http_flow_body`) as proof.
- PROOF = file contents (`root:.*:0:0:`), reflected source, `uid=`, a differential,
  or authenticating as another identity — never just "the parser accepted it".
