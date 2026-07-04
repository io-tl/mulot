# Exposed debug & ops endpoints (Go)

Go services routinely blank-import `net/http/pprof` and `expvar` for their
side-effect registration on `http.DefaultServeMux`, then accidentally serve them
publicly. High-value info disclosure → secrets.

- **pprof** (`/debug/pprof/`): the index lists profiles. Pull with `http_request`:
  - `/debug/pprof/goroutine?debug=2` — every goroutine stack: internal hostnames,
    URLs, in-flight requests, sometimes tokens visible in frames.
  - `/debug/pprof/heap?debug=1` — live objects; strings left in memory.
  - `/debug/pprof/cmdline` — full argv (flags, DB DSNs, secrets passed as args).
  - `/debug/pprof/profile` / `trace` — CPU profile/trace; DoS-y, fetch only if
    explicitly in scope.
- **expvar** (`/debug/vars`): JSON of `cmdline` + `memstats` by default, but apps
  publish custom vars — config, build info, occasionally credentials. Read the
  whole body with `http_request` and grep for `secret`, `token`, `dsn`,
  `password`, `key`, `apiKey`.
- Also worth one extra pull: `/debug/pprof/allocs?debug=1`,
  `/debug/pprof/block?debug=1`, `/debug/pprof/mutex?debug=1` — same value as
  heap/goroutine, occasionally the most revealing (retained strings, lock
  contention on internal endpoints).
- **Prometheus** (`/metrics`): route labels leak internal endpoints, hostnames
  and user ids; `go_info{version=...}` leaks the Go version; counters reveal
  traffic shape and feature flags.
- Behind a path prefix? Re-run the fingerprint `http_fuzz` forced-browse with
  prefixes: `payloads:["debug/pprof/","internal/debug/pprof/","admin/debug/vars",
  "_debug/vars","actuator/...","status"]`.

Evidence: the response-body excerpt (a goroutine frame / argv / custom var)
disclosing internal data or a secret.
Remediation: never register pprof/expvar on the public mux — bind them to a
separate admin listener on localhost, or gate `/debug/*` and `/metrics` behind
auth/network policy; don't blank-import `net/http/pprof` in production builds.
