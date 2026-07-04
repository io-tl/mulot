# Java deserialization

Insecure `ObjectInputStream.readObject()` on attacker-controlled bytes = RCE via
gadget chains. Hunt for serialized blobs in params, cookies, hidden fields, bodies.

1. **Spot the marker**: native Java serialization starts with bytes `AC ED 00 05`.
   - **base64**: starts `rO0AB`. Decode in `browser_evaluate_js` (`atob`) and
     confirm the `\xac\xed` header / readable class names (`java.util.`, `sun.`,
     gadget classes).
   - **hex**: starts `aced0005`. **gzip+base64**: starts `H4sI`.
   - **Content-Type** `application/x-java-serialized-object` on a request/response
     ⇒ a native-deser endpoint.
2. **Where to look**: cookies near `JSESSIONID`, JSF `javax.faces.ViewState`,
   RMI/JMX ports, hidden form fields, any blob above. Pull candidates from
   `http_history` (`body_contains:"rO0AB"`).
   - JSF ViewState: Mojarra encrypts/MACs it by default (not directly
     patchable); MyFaces or a misconfigured `com.sun.faces.ClientStateSavingPassword`
     may leave it as a bare serialized blob — decode first (`atob`) to check
     before assuming it's forgeable.
3. **Confirm injectability**: replay the request with `http_request`/`from_flow`
   and a truncated/garbage blob — a `java.io.StreamCorruptedException` /
   `InvalidClassException` in the response proves the bytes hit `readObject`.
4. **Exploit — prefer command-string gadgets over TemplatesImpl.** A chain
   ending in `TemplatesImpl` needs compiled JVM bytecode you cannot produce
   without `javac`/a JVM — do NOT try to hand-build one (this is where agents
   get stuck). Prefer CommonsCollections1/5/6/7, Groovy, or Clojure chains: the
   command is a plain length-prefixed UTF string inside the object graph, so
   it's patchable without regenerating the payload:
   1. Fingerprint the exact library+version first (skill: fingerprint —
      stacktrace class names, `/actuator/env`/heapdump classpath) to pick the
      matching known chain.
   2. Take a KNOWN published blob for that exact gadget+library version (from
      your training data / a prior write-up) — never invent bytes from scratch.
   3. In `browser_evaluate_js`, decode it (`atob`/`b642b`), locate the command
      as `TC_STRING` (`0x74`) + 2-byte big-endian length + UTF-8 bytes (the
      placeholder command already baked into the blob, e.g. `"id"`), and splice
      in `[0x74, len_hi, len_lo, ...yourCmdBytes]` in its place — the stream has
      no outer length field, so any command length works.
   4. Re-`btoa`, deliver with `http_request` (matching `Content-Type`, or into
      the cookie/hidden field it came from).
5. **Delivery limit**: `http_request`/`http_fuzz` `body`/`headers`/`cookies`
   are plain JSON strings — base64/hex TEXT survives intact (this covers the
   overwhelming majority of real sinks: cookies, hidden fields, params). A raw
   (non-encoded) binary `application/x-java-serialized-object` body will get
   bytes >=0x80 corrupted. Keep the blob base64/hex end-to-end; if the sink
   truly demands an undecorated raw-binary body, say so and pivot — mulot
   cannot send it faithfully.

Evidence: the blob + deserialization stacktrace (or OOB callback) proving readObject.
Remediation: don't deserialize untrusted data; use JSON/DTOs; if unavoidable, a
look-ahead `ObjectInputFilter` (JEP 290) allowlist and patched gadget libraries.
