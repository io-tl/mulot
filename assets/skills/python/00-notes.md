# Python — stack notes

- Flask's dev server (`app.run()`, Werkzeug `run_simple`) is single-threaded/
  blocking by default (`threaded=False`): a timing probe queues behind any
  other in-flight request from the same browser tab (a background XHR, a
  favicon load). Isolate timing-based blind tests — don't navigate/fetch in
  parallel while reading `elapsedMs`/`timeMs`. Django's `runserver` is threaded
  by default; gunicorn/uvicorn workers remove the constraint either way.
- FastAPI/DRF routes expect a JSON body: use `http_request` with
  `headers:{"Content-Type":"application/json"}` and a raw JSON `body`, not a
  browser form post. Watch `http_history` for the `/api/...` calls the
  front-end actually makes.
- Framework shapes the hunt: Django is secure-by-default (CSRF, ORM
  parameterization, template autoescape) so bugs cluster in custom raw-SQL /
  `mark_safe` / DEBUG mode; Flask/FastAPI are minimal, so the app code itself
  is the weak point (SSTI, manual auth, hand-rolled sessions).
- No reflection is not "not exploitable": Werkzeug DEBUG, Jinja2 SSTI, and
  pickle/YAML RCE all have documented BLIND paths (error/length/time side
  channels) in their skill files — read `elapsedMs` (`http_request`) and
  `timeMs` (`http_fuzz`, one row per probe, sent sequentially) before writing
  an input off as not vulnerable.
