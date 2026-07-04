# Server-Side Request Forgery (Go)

Go services are full of outbound `http.Get` / `http.Client.Do` calls: URL
fetchers, webhook senders, image/avatar proxies, link unfurlers, PDF/screenshot
renderers, health checkers, OAuth/OIDC discovery. Any field that becomes a URL
the server fetches is an SSRF candidate — one of the most common Go bug classes.

1. **Find the sink**: params/fields named `url`, `uri`, `link`, `src`, `image`,
   `avatar`, `webhook`, `callback`, `target`, `host`, `feed`, `endpoint`,
   `redirect_uri`, `proxy`. Check `browser_get_form_fields` and JSON bodies in
   `http_flow_body`.
2. **Confirm the fetch**: lacking an external listener, aim at the target's own
   internal ports and read the differential — `http_request` with
   `body:"{\"url\":\"http://127.0.0.1:PORT/\"}"` for the app's admin/db/metrics
   ports; a 200 with internal content (vs a connection-refused error) proves it.
3. **Cloud metadata** (highest impact): fetch
   `http://169.254.169.254/latest/meta-data/` (AWS IMDSv1) and
   `.../latest/meta-data/iam/security-credentials/<role>` for temporary keys;
   IMDSv2 caveat: a 401 on `/latest/meta-data/` is the EC2 token/hop-limit
   guard, not proof the SSRF is fixed — the vulnerable Go code still reaches
   the endpoint, it just can't do the PUT-token handshake unless the app
   itself forwards arbitrary methods/headers. Confirm the sink is still live
   by hitting an internal port instead of closing the finding on a metadata
   401 alone.
   GCP `http://metadata.google.internal/computeMetadata/v1/` (needs request
   header `Metadata-Flavor: Google` — only reachable if the app forwards it).
   Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
   (needs request header `Metadata: true` — set via `http_request` `headers`).
   For a managed-identity token: `http://169.254.169.254/metadata/identity/
   oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`
   with the same header — a 200 with an `access_token` is a full cloud
   credential compromise.
4. **Sweep schemes/hosts** with ONE `http_fuzz` (marker in the url value), read
   status/length deltas: `payloads:["http://127.0.0.1/","http://localhost/",
   "http://169.254.169.254/","http://[::1]/","http://0.0.0.0/","file:///etc/passwd",
   "gopher://127.0.0.1:6379/_","http://2130706433/","http://127.0.0.1.nip.io/"]`.
   Decimal/octal-IP and `nip.io` payloads bypass naive `localhost`/`127.0.0.1`
   string blacklists.
5. **Redirect bypass**: if the fetcher follows redirects (Go's default client
   does, up to 10), an attacker-hosted `302 -> http://169.254.169.254/` reaches
   internal hosts past a host allowlist; probe with `http_request`
   `follow_redirects:true` vs `false`.

Evidence: a response proving the server fetched an internal/metadata resource
(the content, or a timing/status differential vs an unroutable host).
Remediation: validate against an allowlist of hosts/schemes AFTER DNS resolution;
block link-local/loopback/private CIDRs; disable redirects on the fetch client
(`CheckRedirect` returning an error); route egress through a locked-down proxy.
Never blacklist by hostname string.
