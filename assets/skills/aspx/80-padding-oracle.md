# Padding oracle — MS10-070 (ScriptResource.axd / WebResource.axd)

`WebResource.axd?d=<ct>&t=<ts>` and `ScriptResource.axd?d=<ct>&t=<ts>` carry an
AES-CBC ciphertext in `d`. On unpatched ASP.NET (MS10-070) the handler reveals
**valid vs invalid padding** through a response differential, giving a classic
CBC padding oracle — decrypt and **forge** any `d`, then download files
(including `web.config` → `machineKey` → ViewState RCE, skill: viewstate).

## 1. Confirm the oracle (status/length differential)
Take a real `d` (base64-url; `+/=` may be `-_`). Tamper the **second-to-last
byte of the penultimate block** and resubmit.
- Invalid padding → typically **HTTP 500** ("Padding is invalid and cannot be
  removed" pre-patch, or a generic 500).
- Valid padding / wrong content → **HTTP 404 / 200 / 302** — a different
  status or body length.
Sweep all 256 values of one byte position with `http_fuzz`: marker on that byte
inside `d`, `payloads` = the 256 variants, and read the `status`/`length`
columns (or `match_status:404`). A single odd-one-out row = the oracle.

## 2. Decrypt / forge byte-by-byte (CBC math in browser_evaluate_js)
This is hundreds of requests → run it as ONE async loop, not a tool call per
byte. Mirror the crypto-oracle pattern: `browser_evaluate_js` with
`timeout_ms:60000`, an in-page `fetch` loop (or hand byte-batches to
`http_fuzz`), and return only the recovered bytes.
- Standard CBC oracle: for each position `i` in a block, brute the forged
  previous-block byte until padding is valid; then
  `intermediate = forged ^ padValue`, and `plaintext = intermediate ^ realPrev`.
  Do the XOR with the byte↔hex helpers; walk blocks right-to-left.
- To **encrypt** (forge a chosen plaintext, e.g. a request for `web.config`),
  run the oracle backwards to compute each preceding block, prepending a random
  IV block — no key needed.

## 3. Exploit chain
A forged `d` to `ScriptResource.axd` can make `T:WebResource` /
`AssemblyResourceLoader` return arbitrary embedded/served files — the MS10-070
"download web.config" trick. Grab `web.config`, lift `machineKey`, then forge
`__VIEWSTATE` (skill: viewstate) for RCE.

Evidence: the status/length differential proving the oracle + recovered
plaintext or the retrieved `web.config`.
Remediation: apply MS10-070; uniform error handling
(`<customErrors mode="On">`, one error page, same status for all crypto
failures); modern framework with authenticated encryption; rotate `machineKey`.
