# ViewState deserialization (CVE-2020-0688 & unsigned ViewState)

`__VIEWSTATE` is a base64 `LosFormatter`/`ObjectStateFormatter` graph. If it is
unsigned, or signed with a `machineKey` you know, you can craft a malicious graph
that deserializes to RCE (ysoserial.net `ActivitySurrogateSelector` /
`TypeConfuseDelegate` / `TextFormattingRunProperties` gadget on the
`ObjectStateFormatter` formatter).

## 1. Capture & decode
`browser_get_form_fields("form")` → grab `__VIEWSTATE` and
`__VIEWSTATEGENERATOR`. Decode in `browser_evaluate_js`: `atob(vs)` → bytes (use
the byte↔hex helper). The graph starts with `0xFF 0x01` (`\xff\x01`). The trailer
is the MAC.

## 2. Is there a MAC?
- The last **20 bytes** (HMACSHA1) or **32** (HMACSHA256) are the MAC. A blob
  whose length minus the serialized graph leaves a fixed tail ⇒ MAC present.
- Probe: POST back a `__VIEWSTATE` with the **last byte flipped** via
  `http_request from_flow`. Response `Validation of viewstate MAC failed` ⇒ MAC
  enforced (you need the key). No MAC error / it deserializes ⇒ **unsigned**
  (`enableViewStateMac="false"`) ⇒ deserialize-to-RCE directly.

## 3. Known / leaked machineKey → forge (CVE-2020-0688)
If `web.config` leaked the `machineKey` (skill: config), or the app uses a
**static/default** key (the CVE-2020-0688 case — e.g. unpatched Exchange ECP),
sign your own ViewState:
- Build the gadget with **ysoserial.net** (external):
  `ysoserial.exe -p ViewState -g <gadget> -c "<cmd>" --generator=<__VIEWSTATEGENERATOR>
  --validationkey=<K> --validationalg=<ALG> [--decryptionkey/-algo if encrypted]`.
  Note: mulot cannot run ysoserial.net (no .NET/process). Paste a KNOWN
  pre-generated ViewState gadget for the exact machineKey/gadget from your
  training data or a prior write-up, and patch only the command bytes in
  `browser_evaluate_js` (like the Java deserialization skill) — don't build one
  from scratch. No usable pre-generated blob ⇒ report the unsigned/known-key
  ViewState as an UNCONFIRMED lead and pivot.
- Replay it: `http_request from_flow` overriding the `__VIEWSTATE` field in the
  captured POST body. Confirm RCE via an OOB callback or a visible command result.

## 4. ViewStateEncryptionMode
If `__VIEWSTATEENCRYPTED` is present the graph is AES-encrypted too — you need the
`decryptionKey` as well; the same leaked `machineKey` supplies it.

Evidence: the decoded graph showing no MAC tail, or an accepted forged
`__VIEWSTATE` producing command output / OOB hit.
Remediation: patch CVE-2020-0688; keep `enableViewStateMac="true"` (default,
4.5.2+); unique strong random `machineKey` per app; `ViewStateEncryptionMode=
"Always"`; set `ViewStateUserKey`.
