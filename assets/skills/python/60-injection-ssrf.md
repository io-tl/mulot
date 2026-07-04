# Command injection, traversal, SSRF, XXE, open redirect (Python)

Server-side injection where Python passes input to a shell, the filesystem, a
URL fetcher, or an XML parser. Test every param/header/body field; sweep variants
with `http_fuzz`, replay single payloads with `http_request from_flow`.

## OS command injection
Sinks: `os.system`, `os.popen`, `subprocess.*` with `shell=True`. Inject shell
metachars after a value: `; id`, `| id`, `$(id)`, `` `id` ``, `%0a id`. Sweep
with `http_fuzz` (`match_regex:"uid=\\d+"`). A `uid=`/`gid=` in the response ⇒
RCE. Blind: time delay `; sleep 8` and watch the response time.

## Path traversal / arbitrary file read
Sinks: `open(user)`, `send_file`, `os.path.join(root, user)`, static handlers.
Test `?file=`, `?path=`, `?template=`, `?download=`:
`../../../../etc/passwd`, URL-encoded `..%2f..%2f..%2fetc/passwd`, double-encoded
`..%252f`, and Python source `../app.py` / `../settings.py` (leaks SECRET_KEY).
Sweep depths with `http_fuzz`, `match_regex:"root:.*:0:0:"`. Django: a misconfig
`MEDIA_ROOT`/`static` can serve `../`.

## SSRF
Sinks: `requests.get(user_url)`, `urllib.urlopen`, `httpx`, webhook/preview/
import-by-URL features. Point the URL at internal/metadata services:
`http://127.0.0.1:<port>/`, `http://169.254.169.254/latest/meta-data/` (cloud
creds), `http://[::1]/`, `file:///etc/passwd`, `gopher://`. Compare responses /
timing for reachable vs filtered hosts. Read the proxied body from the journal.

Filter bypass via the app's own open redirect (no external host needed): if the
SSRF param is allowlisted by hostname, feed it the SAME app's open-redirect
endpoint pointing at the internal target — `?fetch=http://target.com/redirect
?next=http://169.254.169.254/latest/meta-data/`. Python's `requests` follows
3xx by default, so the allowlist check (sees `target.com`) passes while the
actual fetch lands on the metadata service. Confirm via the proxied body, or
blind via `elapsedMs` — a live internal host answers in ms, a filtered one
times out at your `timeout_ms`.

## XXE (lxml / xml.etree)
If an endpoint accepts XML (`Content-Type: application/xml`, or SOAP/SAML), and
the parser is `lxml.etree` / `xml.sax` with external entities enabled, POST:
`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`
via `http_request`. File contents in the response ⇒ XXE; swap to a
`http://internal` SYSTEM id for SSRF/OOB.

## Open redirect
`?next=`, `?url=`, `?redirect=`, Django `?next=` on login. Set it to
`//evil.com` or `https://evil.com` and check the 3xx `Location` via
`http_request(follow_redirects:false)` or `http_flow`. Off-host Location ⇒ open
redirect (phishing / OAuth token theft).

Evidence: command output, file contents, internal/metadata response, or the
attacker-controlled `Location`.
Remediation: never `shell=True` with input (pass arg lists); resolve+confine
paths under a safe root; allowlist outbound hosts and block link-local/loopback;
`resolve_entities=False` / `defusedxml`; validate redirect targets against an
allowlist (Django `url_has_allowed_host_and_scheme`).
