# SAML — signature wrapping, stripping & comment truncation

SAML SSO trusts a signed XML assertion. Break the trust and you authenticate as
anyone. The `SAMLResponse` is a base64 (sometimes raw-DEFLATE) blob POSTed to the
SP's ACS endpoint.

## Read it first
Decode in `browser_evaluate_js`: `atob(samlResponse)`; if that is binary, it is
DEFLATE — inflate it. Identify `<saml:Assertion>`, the `<ds:Signature>`, which `ID`
it References (the signed element), and the `<saml:NameID>` / attributes that decide
who you are.

## The assertion is also XML — test it for XXE
Before touching signatures, check whether the SP's SAML parser allows a
DOCTYPE. Decode the `SAMLResponse` (`browser_evaluate_js`, `atob`+inflate),
prepend a DOCTYPE+entity to the assertion:
<?xml version="1.0"?><!DOCTYPE saml:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
reference `&xxe;` inside any attribute the SP echoes on error (a rejected/
malformed-assertion page often echoes `NameID` or an attribute), re-deflate/
base64, POST to the ACS with `http_request`. Many SAML toolkits parse the raw
XML BEFORE signature validation, so this can fire even on a now-invalid/unsigned
doc — see `20`/`30` for the exact read technique once the DOCTYPE survives.

## Signature stripping (SP accepts unsigned)
Some SPs verify a signature only *if present*. Remove the whole `<ds:Signature>`,
change `<NameID>` to `admin@target`, re-encode, replay via `http_request`. Landing
as admin ⇒ signatures aren't enforced.

## XML Signature Wrapping (XSW)
The signature stays valid over ID `A`, but you add a second assertion the app
*processes* while validation checks the original. Patterns to iterate:
- Wrap the original signed assertion inside a decoy and add a forged assertion with
  a new ID that the app reads.
- Keep the `Signature` referencing the original (now a child) while a forged
  sibling carries your NameID. There are ~8 canonical variants (XSW-1…8) differing
  in where the forged assertion and the moved signature sit — SP validators fail
  different ones, so try them in turn.

## Comment truncation (CVE-2017-11427 family)
If NameID is `admin@evil.com`, inject an XML comment: `admin@evil.com<!---->` or
`admin<!---->@evil.com`. Some libraries hand the app only the text before the
comment while the canonicaliser validates the whole node ⇒ you become `admin`.

## Also check
`NotOnOrAfter` not enforced (replay), `Audience`/`Recipient` not checked (a token
minted for another SP accepted), and whether the same assertion replays twice.

Evidence: an authenticated SP session as a different / privileged NameID — capture
the resulting session cookie via `browser_get_cookies` or the journal.
Remediation: enforce the signature over the whole response, pin the IdP cert, reject
unsigned/duplicate assertions, validate conditions & audience, and use a
canonicaliser immune to comment truncation.
