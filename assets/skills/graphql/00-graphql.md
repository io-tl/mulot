# GraphQL — capability

Load the moment you see a `/graphql`, `/graphiql`, `/gql`, `/api/graphql` path,
or a JSON body shaped `{"query": "...", "variables": {...}}` — one endpoint
replaces a whole REST surface, so map it before testing anything else.

1. **Discover the endpoint** if not obvious: `http_fuzz` forced-browse
   (`url:"http://host/FUZZ"`, `payloads:["graphql","graphql/","gql","api/graphql",
   "graphiql","altair","playground","v1/graphql"]`, `match_status:200`), then
   confirm with `http_request` POST `body:'{"query":"{__typename}"}'`,
   `headers:{"Content-Type":"application/json"}` — a `{"data":{"__typename":...}}`
   reply confirms it.
2. **Introspection**: POST the standard `IntrospectionQuery`
   (`{"query":"query{__schema{types{name fields{name args{name}}}}}"}`) via
   `http_request` — a full schema dump (types/mutations/args) is a finding and
   your map for every next step. If disabled, probe field names one at a time
   with `http_fuzz` (marker as a bogus field name) and read the
   `"Did you mean \"FUZZ\""` suggestion error — it leaks real field names even
   with introspection off.
3. **Batching / aliasing to dodge rate limits**: a single HTTP call can carry
   MANY operations — `{"query":"{ a1:login(user:\"a\",pass:\"p1\"){token} a2:login(user:\"a\",pass:\"p2\"){token} ... }"}`
   tries dozens of passwords/OTPs/coupon codes in ONE request, bypassing a
   per-request lockout. Build the aliased body yourself (a1..aN) and send with
   `http_request`; this beats `http_fuzz`'s one-payload-per-request model.
4. **Injection**: fuzz string ARGUMENTS inside the query/variables — SQL
   (`' OR '1'='1`), NoSQL (`{"$ne": null}` as a variable value), OS/template
   payloads — with `http_fuzz` (marker inside the JSON `body`), reading errors
   or data-length deltas exactly like a REST body param.
5. **Authorization**: replay an admin mutation (`deleteUser`, `updateUserRole`)
   discovered via introspection using a low-priv/no token (`http_request` with
   that mutation body and `use_session:false` or another user's cookie) —
   success ⇒ broken function-level access control (see skill: api if loaded).
6. **DoS caution**: do NOT actually send a deeply-recursive/nested query as
   proof — one 3-4 level nested query demonstrating the LACK of a depth/cost
   limit error is enough; do not run it to exhaustion against a live target.

Evidence: the dumped schema, the extracted data, or the admin action executed
with a low-priv token.
Remediation: disable introspection in production, enforce query depth/cost
limits, authorize every field/mutation server-side (not just the top query),
rate-limit per OPERATION not per HTTP request (blocks alias/batch abuse).
