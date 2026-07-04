# Java — stack notes

- Java injection frequently lands in HEADERS, not just params/body: also fuzz
  `User-Agent`, `Content-Type`, `X-Forwarded-For`, `X-Api-Version` (Log4Shell,
  OGNL, header-based EL).
- Decode Java serialized blobs (`rO0AB...` base64 / `aced0005` hex) inside
  `browser_evaluate_js` before reasoning about gadget chains.
