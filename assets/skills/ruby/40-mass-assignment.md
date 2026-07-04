# Mass assignment / strong-params bypass (Rails)

Rails maps form params straight onto model attributes. If a controller permits
too much (or uses `params.permit!` / `update(params[:user])`), an attacker sets
fields that were never on the form — `admin`, `role`, `account_id`,
`approved`, `credits`, `user_id`.

1. **Find the model + its real columns**: submit/edit a record, capture the
   POST/PATCH with `http_history` → `http_flow` (note the `user[...]` /
   `<model>[...]` param shape). Guess privileged attributes from naming
   (`admin`, `role`, `is_admin`, `verified`, `owner_id`) and confirm via error
   traces or `/rails/info/routes`.
2. **Inject extra params**: replay the captured request with `http_request
   from_flow`, adding the unexpected field to the body, keeping the
   `authenticity_token` and session:
   `body:"user[name]=x&user[admin]=true&authenticity_token=<tok>"`. Then re-read
   the record (or hit an admin-only page) to see if it took.
3. **Sweep candidate fields** with `http_fuzz`: marker as the attribute name,
   `body:"user[FUZZ]=true&authenticity_token=<tok>"`,
   `payloads:["admin","is_admin","role","superuser","approved","verified",
   "account_id","user_id","credits","price"]`; watch for a 200/302 (accepted) vs
   422 (rejected by strong params) and post-state changes.
4. **Nested / relation injection**: `user[role_ids][]=1`,
   `order[user_id]=<victim>`, `comment[user_id]=1` to reassign ownership or grant
   roles. Also try array vs scalar type confusion (`user[admin][]=true`).
5. Confirm by reading back the changed attribute (privilege actually granted),
   not just the HTTP status.

6. **JSON API bodies** (Rails API-only / `respond_to :json`): same strong-params
   bypass, JSON-shaped — no `authenticity_token` needed (CSRF is skipped for
   JSON requests by default): `http_request(method:"PATCH",
   url:".../api/users/me", headers:{"Content-Type":"application/json",
   "Authorization":"Bearer <tok>"}, body:'{"user":{"name":"x","admin":true}}')`.
   Sweep the same candidate-field list with `http_fuzz`, marker inside the JSON:
   `body:'{"user":{"FUZZ":true}}'`.

Evidence: the request that set a non-form attribute + the record/page proving it
took effect (e.g. now an admin).
Remediation: strict `params.require(:user).permit(:name, :email)` — never
`permit!` or pass raw `params`; keep privileged attributes out of mass-assignable
sets and set them server-side with explicit authorization.
