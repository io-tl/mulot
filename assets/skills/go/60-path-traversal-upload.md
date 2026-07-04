# Path traversal & malicious upload (Go)

## Traversal
Sinks: `http.ServeFile(w,r, userPath)`, `os.Open(filepath.Join(base, name))`,
`os.ReadFile`, static handlers over `http.Dir` with a tainted name. Note:
`filepath.Join` cleans `..` but does NOT confine to base — `Join("/srv", input)`
still escapes if `input` is absolute or climbs past base.

- Test any `?file=`, `?path=`, `?name=`, `?template=`, `?download=`, `?lang=`,
  or a path segment that maps to a file.
- Sweep depths/encodings in ONE `http_fuzz` (`url:".../?file=FUZZ"`,
  `match_regex:"root:.*:0:0:"`): `payloads:["/etc/passwd",
  "../../../../etc/passwd","..%2f..%2f..%2fetc%2fpasswd",
  "..%252f..%252fetc%252fpasswd","%2e%2e/%2e%2e/etc/passwd",
  "....//....//etc/passwd","/proc/self/environ"]`. A matched row pins the bug;
  `/proc/self/environ` often leaks env secrets.
- `http.ServeFile` rejects a literal `..` in the *URL path* (400) but NOT `..`
  arriving via a query/JSON param or already-decoded — target those. Windows:
  `..\..\` and absolute `C:\`.
- **Directory listing**: request the upload/static dir bare (`/uploads/`,
  `/static/`, `/files/`) — Go's `http.FileServer(http.Dir(...))` auto-renders
  an HTML index when the folder has no `index.html`, leaking every filename
  inside. A bare `<pre>`/`<a href=` listing in the body is the tell — no
  traversal payload needed.

## Upload / zip-slip
If an `input[type=file]` or multipart endpoint exists:
1. Upload with `browser_upload_file` (or an `http_request` multipart body). Go
   won't execute an uploaded handler file, but test: path escape via a crafted
   filename (`../../evil` overwriting config), and stored XSS via an inline-served
   SVG/HTML upload (check the response `Content-Type`/`Content-Disposition`).
2. **Zip-slip**: if the app extracts archives (`archive/zip`, `archive/tar`),
   upload one whose entry name is `../../tmp/evil` — the stdlib does NOT sanitize
   entry paths, so a naive `filepath.Join(dest, hdr.Name)` writes outside `dest`.
   Confirm by reading the planted file back via the app.
3. **Decompression bomb**: a nested/highly-compressed archive probes resource
   limits — test gently, do not DoS.

Evidence: file contents read from outside the webroot, or a file written/served
from an unintended path.
Remediation: after joining, verify the cleaned absolute path is still under base
(`strings.HasPrefix(filepath.Clean(p), base+string(os.PathSeparator))`); reject
`..`/absolute paths in archive entry names; cap extracted size/count; serve
uploads from a non-executable dir with a forced `Content-Type` + attachment
disposition.
