# Crypto: ECB / CBC / padding oracles

When the app hands you ciphertext you partly control (an encrypted `query`,
token, or cookie), you can often inject or decrypt without the key. PHP apps
love AES-ECB on a SQL string (e.g. OverTheWire natas28).

## 1. Spot it
- Find the blob. If it sits in a **redirect** (a 3xx `Location`), JS `fetch`
  CANNOT read it (opaque redirect) — use one of:
  - normal nav/submit, then `http_history(status:302)` → `http_flow(id)`
    to read the captured `Location` (also works for Set-Cookie, WWW-Authenticate);
  - or `http_request(..., follow_redirects:false)` and read `Location`
    directly (best when you script the whole attack).
  Encrypted **cookie** → `browser_get_cookies`; encrypted body field → the body.
- base64/hex-decode it inside `browser_evaluate_js` — use the byte↔hex↔base64
  helper from that tool's description (`b642b`/`b2h`) so raw bytes survive the
  latin1 `atob` trap. Length a multiple of **16** (or 8) ⇒ a block cipher.
- Submit a long run of one character. If two **adjacent ciphertext blocks become
  identical**, it is **ECB** (identical plaintext blocks → identical ciphertext).
  CBC won't repeat.

## 2. Map the structure — in ONE evaluate_js loop, CONCURRENT
Don't make a tool call per length, and don't loop sequentially over an external
host (it blows the 30 s timeout). Fire all lengths with **`Promise.all`** and
pass **`timeout_ms: 60000`** to browser_evaluate_js. To read the ciphertext
in-page, `fetch(index.php, {redirect:'follow'})` and read **`resp.url`** (the
final `search.php?query=<ct>`) — `fetch` cannot read the 302 `Location`.
For n = 0..48 decode the ct, split into 16-byte blocks (use `charCodeAt`), and
return `{n, len, blocks:[hex...]}`. From that ONE result, reason out:
- **block size**: `len` jumps by 16 when n crosses a boundary.
- **prefix length**: the first blocks are constant (they hold the fixed prefix).
  A block becomes constant once your filler fully covers it, and two adjacent
  blocks become identical when your filler spans 32 aligned bytes — both pin
  down where your input starts. (Worked example: prefix 38 = 2 constant blocks
  (32 B) + 6 B into block 2; block 2 constant from n=10; blocks 3,4 equal at n=48.)
- **escaping**: at the length just below a 16-boundary, append `'` then `\`;
  if `len` jumps a block, that char became 2 bytes (escaped) — plan around it.

## 3. ECB cut-and-paste exploitation — worked recipe
Each block decrypts independently, so you may **reorder, duplicate, or drop**
ciphertext blocks. The quote you need to break the SQL string gets escaped to
`\'`; free it by making its `\` the LAST byte of a block you fully control, then
**drop that block**.

Recipe (prefix P, block size 16; here P=38):
1. Pad so the byte AFTER your filler is block-aligned and entirely yours:
   `input = "A"*(16 - P%16)` fills to the next boundary (P=38 → 10 A's).
2. Add a full controlled block that will end in the escaping `\`:
   `+ "B"*15 + "'"`. After escaping, the 15 B's + `\` fill one block (the one to
   drop), and the `'` starts the NEXT block.
3. Append the injection (no quotes/backslashes — use a `#` comment and hex
   literals): `+ " UNION SELECT <cols> #"`.
4. Encrypt that input (POST to index.php, read the redirect ct), split into
   blocks, and **drop the block index that holds `"B"*15 + "\"`** (here index 3:
   bytes 48–63). Concatenate the rest into the malicious ciphertext.
5. Submit it to the consumer (`http_request` GET `search.php/?query=<b64>`)
   and read the result. Decrypted SQL becomes `…LIKE '%AAAAAAAAAA' UNION SELECT … #…`.

Then: find the **column count** with `… UNION SELECT 0x41 #`, `…,2 #`, … (the one
that displays your marker). Enumerate with `information_schema` and dump
(`group_concat(...)`). Passwords often sit in a plain `users(username,password)`
table — check it before reaching for `LOAD_FILE`.

## 4. Padding oracle (CBC)
If the app reveals padding-valid vs invalid differently (status/error/length),
you can decrypt or forge any plaintext byte-by-byte. This is hundreds of
requests → run it as ONE async loop (`browser_evaluate_js` / `http_request`)
and return only the recovered bytes, not every response.
