# Ruby / Rails — stack notes

- State-changing POST/PATCH/DELETE in Rails needs the `authenticity_token` AND
  the session cookie: read the token from the form, or replay a captured
  `from_flow` (which already carries both).
- Decode/forge the Rails session cookie (signed `payload--HMAC`, or AES-GCM
  encrypted) and Marshal/YAML blobs inside `browser_evaluate_js`.
