# SOAP & XML-RPC — protocol-specific abuse

Beyond generic XXE/XPath in the envelope body, SOAP and XML-RPC each have
their own transport-level bugs — test these once `10` has fingerprinted the
endpoint.

## SOAPAction / body routing confusion
Some SOAP stacks dispatch on the `SOAPAction` header, others on the body's
first child under `<soap:Body>` — often only ONE of the two is
authorization-checked. Capture two calls to different operations (one
privileged, one not) via `http_history`, then with `http_request` replay the
LOW-privilege body under the HIGH-privilege `SOAPAction` header (and vice
versa). A 200 without `<soap:Fault>` on the mismatched pair reached an
operation your header/body pair shouldn't reach.

## WS-Security weaknesses
If `<soap:Header>` carries a `<wsse:Security>` block:
- Strip it, or send an empty `<wsse:UsernameToken>` — some services only
  validate WS-Security IF a token is present at all.
- Send an expired `<wsu:Timestamp>` (`Expires` in the past) — accepted ⇒
  replay window not enforced.
- The signed part is XML-signed the same way SAML is — the XSW technique in
  `60` (wrap the signed node, add a forged sibling the app reads) applies
  verbatim to SOAP requests/responses.

## XML-RPC (WordPress `/xmlrpc.php` and others)
- `system.multicall` batches many `<methodCall>`s in ONE HTTP POST — bundle
  hundreds of login/`wp.getUsersBlogs` attempts per request to bypass a
  per-HTTP-request rate limit or lockout counter.
- `pingback.ping(sourceURI, targetURL)` makes the SERVER fetch `sourceURI` —
  blind SSRF/port scan with no listener needed: point it at
  `http://127.0.0.1:<port>/` and diff the SOAP-fault text/timing (`faultCode 0`
  vs `16` "cannot access" vs timeout) across ports — same differential method
  as `30`'s blind SSRF confirmation.

Send both with `http_request`, `Content-Type: text/xml`; read `http_flow_body`.
Evidence: an operation reached under the wrong SOAPAction, an
expired-timestamp request accepted, a port-scan differential, or a login
bypassing lockout via multicall. Remediation: dispatch on ONE authenticated
value only, enforce WS-Security timestamp/signature over the whole message,
disable `system.multicall`/pingback or rate-limit per contained call.
