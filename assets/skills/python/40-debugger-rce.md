# Werkzeug debugger console RCE (DEBUG=True)

Flask/Werkzeug apps run with `app.run(debug=True)` or `FLASK_DEBUG=1` ship the
**interactive debugger**: any unhandled exception returns a 500 page that hosts a
Python console executing arbitrary code in the server process. High severity,
trivial RCE.

1. **Detect**: trigger an exception (bad type in a param, e.g. `?id=abc` where an
   int is expected, or hit a route that raises). The 500 body is titled
   **"Werkzeug Debugger"** and lists traceback frames each with a small console
   icon. Read it via `http_flow_body` on the 500 flow from `http_history`.
2. **Open a console**: each frame exposes `/console` (or `?__debugger__=yes&
   cmd=...&frm=<n>&s=<secret>` AJAX endpoint). In the browser, `browser_navigate`
   to the debugger page, `browser_snapshot`, click a frame's console `ref`, then
   `browser_type` Python into the prompt and submit.
3. **Run code**: in the console evaluate
   `__import__('os').popen('id').read()` or
   `import subprocess; subprocess.check_output(['id'])`. Read the output.
4. **The PIN, computed not guessed** — Werkzeug derives it from a SHA1 over, in
   order (skip unknowns): the process OS username, the module name
   (`flask.app`), the app class name (`Flask`), the absolute path of Werkzeug's
   `app.py` (leaked via a traceback frame or an LFI on `.../flask/app.py`), the
   MAC address as a full decimal integer (`uuid.getnode()`), and the machine id
   (`/etc/machine-id` or `/proc/sys/kernel/random/boot_id`, via any LFI).
   Concatenate the UTF-8 bytes of each known bit + the literal bytes `cookiesalt`
   and `pinsalt`, SHA1 the whole (`crypto.subtle.digest('SHA-1', ...)` in
   `browser_evaluate_js`), read the digest as a big decimal
   (`BigInt('0x'+hex)`), take the first 9 digits, group `XXX-XXX-XXX`. Submit
   once: `http_request` to `/?__debugger__=yes&cmd=pinauth&pin=<pin>&s=<secret>`;
   an `{"auth":true}` unlocks `/console` to script the RCE.

Use `http_request` to fetch the `__debugger__` AJAX endpoint directly once you
have the frame id + secret, so you can script commands without the UI.

Evidence: the "Werkzeug Debugger" page + `id`/command output from `/console`.
Remediation: never run with `debug=True` / `FLASK_DEBUG=1` in production; run
under gunicorn/uvicorn with debugging off; set a real error handler.
