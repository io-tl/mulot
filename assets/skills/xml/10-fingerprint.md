# Find the XML sinks

Before any payload, locate every place attacker XML reaches a parser.

## From the traffic journal
- `http_history`, then narrow to any flow whose request/response is
  `Content-Type: application/xml`, `text/xml`, `application/soap+xml`,
  `application/rss+xml`, `application/xml-dtd`, or whose body starts with `<?xml`.
- SOAP: requests carrying a `SOAPAction` header or a `<soap:Envelope>` body; a
  `?wsdl` endpoint describes every operation and its parameter types — GET it with
  `http_request` and read the schema for injectable string fields.
- SAML: a base64 (often DEFLATE-compressed) `SAMLResponse`/`SAMLRequest` form field
  POSTed to `/acs`/`/saml/consume`/`/sso`. Decode in `browser_evaluate_js` (`atob`,
  then inflate if it is raw-deflate) to see the assertion → see `60`.
- XML-RPC: `POST /xmlrpc.php` (WordPress) or any `<methodCall><methodName>` body.

## By probing
- A JSON API often *also* accepts XML: resend a captured JSON flow via
  `http_request` with `Content-Type: application/xml` and an equivalent XML body —
  if it parses, the XML path is usually less hardened than the JSON one.
- Upload forms: `.svg` (rendered/rasterized server-side → XXE), `.docx`/`.xlsx`
  (OOXML = a zip of XML parts), `.xml` import. Use `browser_get_form_fields` to
  find the file input.
- Feed/sitemap importers, "import settings", "load from URL" features.

## Confirm it is really parsing XML (not storing a blob)
Send a well-formed doc with a deliberate well-formedness error (an unclosed tag).
A 500 / "parse error" / "premature end of data" in the response ⇒ a live parser is
reading your input — the precondition for XXE/XPath/XSLT. A silent 200 that stores
it verbatim ⇒ think stored-XSS / second-order, not XXE.
