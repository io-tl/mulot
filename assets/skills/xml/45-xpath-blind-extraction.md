# Blind XPath — schema discovery & full-record dump

Use once `40` confirms a blind boolean oracle but naive per-character guessing
on a GUESSED field name stalls. Confirm the schema first, then dump every
record systematically instead of guessing forever.

## 1. Discover structure before guessing field names
Don't assume `//user[1]/password` exists — enumerate it blind:
```
' and name(/*[1])='users' and 'a'='a                  root element name
' and count(/*/*[1]/*)=4 and 'a'='a                   fields per record (children)
' and name(/*/*[1]/*[1])='username' and 'a'='a         1st field name
' and count(/*/*[1]/@*)=2 and 'a'='a                   OR: fields are ATTRIBUTES
' and name(/*/*[1]/@*[1])='password' and 'a'='a        attribute name variant
```
If both element and attribute guesses fail, try both node tests
(`*[1]/text()` vs `*[1]/@*[1]`) before concluding the field doesn't exist.

## 2. Dump every record, not just the first
`count(//user)=N` gives the total (see `40`). Loop `i` = 1..N, and for each `i`
loop over EVERY field found in step 1 — two nested loops, not one call: one
`http_fuzz` run per (record, field, position).

## 3. Cut per-position requests with a membership bisection
A full charset sweep is ~95 calls per char. Halve it instead: test whether the
char is IN a candidate half via `translate()` deletion —
`string-length(translate(substring(pwd,N,1),'abcdefghijklm',''))=0` is true
only if the char is one of `a-m`. Repeat on the surviving half (~7 calls to
pin one char instead of 95).

## 4. Stop condition
`string-length(...)=k` false for increasing k ⇒ length found; a position whose
FULL sweep matches nothing ⇒ wrong field name from step 1 — back out, don't
loop forever.

Evidence: reconstructed values confirmed by a later authenticated login/lookup.
Remediation: see `40`.
