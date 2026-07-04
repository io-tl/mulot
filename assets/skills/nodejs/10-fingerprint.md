# Fingerprint a Node.js stack

Confirm Node.js and identify the framework/runtime to choose targeted tests.

Gather signals with `browser_navigate`, `browser_get_cookies`, `scan_passive`
(its `headers` section), `http_flow` (response headers), and `http_request`:

- **Headers**: `X-Powered-By: Express` ⇒ Express (finding — should be disabled).
  `X-Powered-By: Next.js`, weak `ETag` hashes, a `Server: nginx` front is common.
  Absent `X-Powered-By` does NOT rule Node out.
- **Cookies** (`browser_get_cookies`): `connect.sid` ⇒ express-session.
  `koa.sess` / `koa.sess.sig` ⇒ Koa. `next-auth.session-token` ⇒ NextAuth.
  A JWT-looking value (`eyJ...`) ⇒ go to skill: auth-session-jwt.
- **Errors**: trigger a 500 (bad content-type, missing field, array where a
  string is expected) and read the body with `http_flow_body`. A JSON
  `{"error":...}` or an HTML stacktrace with `at Object.<anonymous>`,
  `node_modules/`, `/express/lib/router/` confirms Node and leaks paths/versions
  (finding — `NODE_ENV` is not `production`).
- **Next.js / React**: `/_next/static/`, a `__NEXT_DATA__` script blob (read it —
  props often leak server data), `.js.map` source maps (recover server source).
- **Realtime**: `/socket.io/?EIO=4&transport=polling` returning a handshake
  (`0{"sid":...`) ⇒ Socket.IO websockets in play.
- **GraphQL**: a `/graphql` or `/api/graphql` POST returning `{"data":...}`/
  `{"errors":...}` for `{"query":"{__typename}"}` ⇒ GraphQL API — load the
  `graphql` capability (`load_skill(["graphql"])`) and test it with the
  resolver/injection method, not REST-style params.
- **Forced-browse common files** in ONE `http_fuzz` (`url:"http://host/FUZZ"`,
  `match_status:200`): `payloads:["package.json","package-lock.json",".env",
  ".git/config","api","api-docs","server.js","app.js","_next/static",
  "main.js.map","yarn.lock"]`. `package.json` lists every dependency+version
  (cross-ref known CVEs); `.env` leaks secrets — each a finding.

Record: framework (Express/Koa/Fastify/Nest/Next), Node version if leaked,
exposed package.json/.env/source maps (each a finding), and `X-Powered-By`
disclosure (low — remove it).
