# Type juggling & loose comparison (PHP)

PHP's `==` coerces types before comparing; a string that LOOKS numeric
("0e1234...") is treated as a float, and `0`/`false`/`null` loosely equal many
non-numeric strings pre-PHP8. Auth/token/hash checks written with `==` instead
of `===` (or `hash_equals()`) are bypassable without knowing the secret. Confirm
the PHP version first (10-fingerprint) — PHP 8 tightened number-vs-string
comparison and this class narrows.

1. **Spot the sink**: a login/API-key/CSRF check comparing a hash, token, or id
   with `==`, `in_array()` (default non-strict), or a `switch` on a hashed
   value — read the source if exposed (`.phps`, backup file, LFI) or infer.
2. **Magic hash (md5/sha1 `==`)**: if the app does
   `if ($_POST['password'] == $stored_md5_or_sha1)`, submit a value whose
   md5/sha1 ALSO starts `0e` + only digits — both sides cast to float `0`,
   equal. Known inputs: `240610708` (md5 → `0e462097431906509019562988736854`),
   `QNKCDZO` (md5 → `0e830400451993494058024219903391`). Try both with
   `http_request` on the login POST body.
3. **`strcmp()`/`md5()` array bypass**: send the compared field as an ARRAY —
   `password[]=x` instead of `password=x`. `strcmp($_POST['password'], $real)`
   or `md5($_POST['password'])` then receives an array; on PHP <8 both return
   `NULL`, and `NULL == 0`/`NULL == false` — many `if (strcmp(...) == 0)` or
   `if (!md5(...))` checks pass. On PHP 8 this throws a `TypeError` instead
   (visible in the response) — a fatal error there rules the bypass out.
4. **`in_array()`/`switch` loose bypass** (PHP <8): `in_array($input,
   ['admin','superuser'])` or `switch($input)` with non-numeric `case`
   strings — submitting `0` or `false` loosely equals any non-numeric-string
   member.
5. Sweep 2–4 in one `http_fuzz` on the field, `payloads:["0",
   "0e462097431906509019562988736854","240610708","QNKCDZO","false"]`, plus a
   second call sending the param as `field[]=x`. `match_regex` on the
   post-login success indicator.

Evidence: authenticated response / success indicator after the bypass payload.
Remediation: `===`/`hash_equals()` for ALL secret/hash/token comparisons, never
bare `==`; reject array input on scalar-typed fields before comparing.
