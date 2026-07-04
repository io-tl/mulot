# PHAR deserialization (phar:// stream wrapper)

`unserialize()` isn't the only trigger for PHP object injection: ANY filesystem
function (`file_exists`, `is_file`, `file_get_contents`, `fopen`, `copy`,
`filemtime`, `md5_file`, `getimagesize`, `exif_read_data`, ...) called on a
`phar://` path auto-unserializes that PHAR's metadata — no `unserialize()` call
needed in app code at all. `phar.readonly` does NOT block this (it only gates
WRITING new archives via the `Phar` class). No PHP CLI available in mulot —
hand-craft the archive bytes; there is no shortcut.

## 1. Find the trigger
A user-controlled path reaching a filesystem function, PLUS a way to get
attacker bytes onto disk (a file upload, even one restricted to images — the
extension/MIME doesn't matter, only `phar://` cares about content). Common
combo: an avatar/thumbnail upload followed by `getimagesize()` or a
`file_exists()` check on `phar://uploads/<file>/whatever`.

## 2. Craft the archive in `browser_evaluate_js`
Same NUL-safe base64 approach as `45-object-injection.md` (b2b64 helper), for
binary framing instead of the serialize grammar.
1. **Stub**: any bytes, MUST contain `__HALT_COMPILER();` then `?>` then a
   newline. To pass an image check, prefix a real magic number:
   `GIF89a` + `<?php __HALT_COMPILER(); ?>\n` (phar parsing scans for
   `__HALT_COMPILER();` anywhere, ignoring what precedes it).
2. **Manifest** (ints little-endian uint32 unless noted): manifest length,
   file count (`1`), API version (`\x11\x00`), global flags (`0`), alias
   length+alias (`0`,``), archive metadata length+data (`0`,``); then per
   file: filename length+name, uncompressed size, mtime, compressed size
   (= uncompressed, no compression), CRC32 of the file contents, flags (`0`),
   **metadata length + `serialize(new Gadget(...))`** — THIS is the sink.
3. **File contents**: any bytes matching the declared size, right after the
   manifest. No signature block needed (skip the `0x10000` global flag bit).
4. Reuse the `45-object-injection.md` gadget-finding steps (magic methods,
   NUL-mangled private props) to build the metadata's `serialize()` payload.

## 3. Deliver and trigger
Upload the crafted bytes (`browser_upload_file`) as the image field, then get
the app to touch `phar://<path-to-uploaded-file>/x` through the vulnerable
sink (path traversal, a filename you control, or a predictable upload path).
`http_request` the triggering endpoint, then read the gadget's side effect
via `http_flow_body`.

Evidence: the gadget's side effect (written file served, or data dumped)
after the `phar://` access — not the upload succeeding.
Remediation: validate uploaded file CONTENT (magic bytes) even for images;
never pass user-influenced paths to filesystem functions where a `phar://`
prefix is reachable; upgrade to a PHP version with hardened phar metadata
checks.
