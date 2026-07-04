# Go — stack notes

- Go bugs cluster in logic/config, not memory: SSRF, IDOR, exposed debug
  endpoints (`/debug/pprof`, `/debug/vars`, `/metrics`), JWT, mass assignment.
  Weight the hunt accordingly.
- Go is quiet on banners: lean on NEGATIVE fingerprints (default 404 bodies,
  `goroutine ... [running]:` panic stack traces) to confirm the stack.
