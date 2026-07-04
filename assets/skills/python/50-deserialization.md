# Insecure deserialization (pickle, PyYAML)

Untrusted bytes fed to `pickle.loads`, `yaml.load`, `jsonpickle`, or
`shelve`/`marshal` give RCE on deserialization. Look in cookies, hidden form
fields, query params, and request bodies for serialized blobs.

## Spot it
- **pickle**: base64 that decodes to bytes starting `\x80\x04` (proto 4) or
  `\x80\x05` — base64 of those begins `gASV` / `gAWV` (proto 4/5) or `gAJ`/`gAN`
  for older protos; ends in `.` Decode/inspect inside `browser_evaluate_js`
  (`atob`, then the byte→hex helper) — a pickle opcode stream (`c__main__`,
  `Vstring`, `os\nsystem`) confirms it. Common in custom session cookies that are
  NOT signed (or signed with a known key).
- **PyYAML**: a param/body containing YAML, especially if the app uses
  `yaml.load(data)` without `Loader=SafeLoader`.

## Exploit
- **pickle**: a malicious pickle whose `__reduce__` returns `(os.system, ('id',))`
  runs `id` on load. No Python/pickle library needed — protocol-0 pickle is
  plain ASCII opcodes you can type directly: for `os.system('id')` the exact
  byte sequence is `cos\nsystem\n(S'id'\ntR.` (GLOBAL os.system, MARK, STRING
  'id', TUPLE, REDUCE, STOP). Build the string in `browser_evaluate_js`, swap
  `id` for any single-quote-free command — `sleep 5` for a blind proof (read
  `elapsedMs`), or `id > /app/static/o.txt` to exfiltrate through a served path
  — `btoa()` it, and place it where the original blob sat: replay with
  `http_request from_flow` (override the cookie/param). You usually need the
  signing key first (skill: session-jwt) if the blob is HMAC-signed.
- **PyYAML**: submit
  `!!python/object/apply:os.system ["id"]` (or
  `!!python/object/apply:subprocess.check_output [["id"]]`) as the value via
  `http_request`. If `yaml.load` is unsafe, the command runs server-side.

Use `browser_evaluate_js` to base64-encode the crafted payload and to decode the
response. Read RCE output from the response body or, for blind cases, an
out-of-band/timing signal.

Evidence: the crafted blob + command output (or timing proof) in the response.
Remediation: never unpickle untrusted data; use JSON; `yaml.safe_load` only;
sign+verify any serialized state with a secret the client never sees.
