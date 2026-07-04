# API access control: BOLA, mass assignment, function-level — capability

Load on any JSON REST surface, whatever the backend: `/api/`, `Content-Type:
application/json` bodies, or an OpenAPI/Swagger doc (`/openapi.json`, `/swagger`,
`/api-docs`). These bugs live in the app's authorization logic, not the language.

1. **Map the surface**: fetch `/openapi.json`/`/swagger.json` with `http_request`
   if present (full route+schema dump); otherwise collect JSON routes from
   `http_history` as you browse the SPA/app, and forced-browse common ones with
   `http_fuzz` (`wordlist:"pages"` or a custom API-path list, `match_status:200`).
2. **BOLA / IDOR**: capture an authenticated request for YOUR object
   (`http_history`), replay it with `http_request from_flow` swapping only the
   id, or with another user's `cookies`/token (`use_session:false`). Still
   returns/accepts ⇒ broken object-level authorization. Sweep the id space in
   one `http_fuzz` call (marker on the id, a numeric/UUID range).
3. **Broken function-level authorization**: replay an admin/staff-only route
   (`/api/admin/...`, a `DELETE`/`PUT` a normal user's UI never exposes) using a
   LOW-PRIV token — `http_request` with `method` swapped and the low-priv
   session. A 200 where a 403 is expected ⇒ vertical privilege escalation. Also
   try raw HTTP verb tampering on a GET-only route (`POST`/`PUT`/`PATCH`).
4. **Mass assignment**: replay a create/update body (`from_flow`) with extra
   JSON keys the form never shows: `{"role":"admin","is_admin":true,
   "balance":99999,"verified":true,"user_id":<victim>}`. Re-fetch the object
   afterward — a persisted privileged field ⇒ mass assignment (over-binding).
5. **Excessive data exposure**: diff the RAW API response (`http_flow_body`)
   against what the UI actually renders — extra keys like `password_hash`,
   `ssn`, `internal_notes`, `is_admin` present in JSON but hidden client-side is
   a finding on its own even without further exploitation. `scan_passive
   (include_network:true)` also flags secrets in journaled bodies.

Evidence: the cross-account/tampered request + the response proving the data
leak or privilege change (re-fetch the object to confirm persistence, not just
the HTTP status).
Remediation: per-object ownership checks on every handler (not just auth
middleware), explicit response DTOs/serializers (never return the DB model
raw), allow-listed writable fields (never bind the full request body), and
authorization checks on every method/route including ones the UI doesn't link to.
