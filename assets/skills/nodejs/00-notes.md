# Node.js — stack notes

- Most Node bugs need a JSON body a browser form cannot express: use
  `http_request` with `headers:{"Content-Type":"application/json"}` and a raw
  `body` (or build a `fetch` in `browser_evaluate_js`) to smuggle operator,
  `__proto__`, and nested-object payloads.
- Application logic lives in the JSON `/api/...` routes the front-end calls —
  watch `http_history` for them and test those, not just the rendered pages.
