# PHP — stack notes

- Read the PHP version off `X-Powered-By` / error pages FIRST (10-fingerprint) —
  it gates which bugs below even apply: loose-comparison magic hash and the
  `0 == 'string'` bypass work PHP <8 only (PHP 8 tightened number/string
  comparison); `create_function()`/`preg_replace(..., '/e', ...)`/`assert()`
  string-eval are PHP <7/<8-only (removed later).
- `register_globals=On` (ancient PHP <5.4, still seen on legacy/CTF boxes):
  every `$_GET`/`$_POST`/`$_COOKIE` key becomes a global variable — try
  overwriting an internal flag by name (`?authenticated=1`, `?is_admin=1`,
  `?debug=0`) even where no such param is documented. `extract($_GET)` /
  `parse_str($_SERVER['QUERY_STRING'], $x)` without a prefix reproduce the
  same bug in modern code — same test applies.
- See `25-type-juggling.md` for loose `==`/`strcmp()`/`in_array()` bypasses and
  `35-code-injection.md` for `preg_replace()`/`assert()`/`create_function()`/
  `call_user_func()` sinks — both common on legacy PHP CTF-style targets.
