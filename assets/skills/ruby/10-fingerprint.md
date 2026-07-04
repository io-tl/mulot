# Fingerprint a Ruby stack

Confirm Ruby and identify Rails vs Sinatra, version, and app server to choose
targeted tests. Gather signals with `browser_navigate`, `browser_get_cookies`,
`scan_passive` (its `headers` section), `http_request`, and `http_flow`.

- **Cookies**: a `_<app>_session` cookie (e.g. `_myapp_session`) ⇒ Rails. Its
  value is URL-encoded base64 `payload--HMAC` (JSON if unencrypted, or AES-GCM if
  `cookies.encrypted`). `rack.session` ⇒ Rack/Sinatra. Decode it in skill:
  session-cookie-crypto.
- **Form field**: a hidden `authenticity_token` (and `<meta name="csrf-token">`)
  ⇒ Rails CSRF protection — read it with `browser_get_form_fields`.
- **Headers** (`http_flow` / `scan_passive`): `X-Runtime` (request seconds) and
  `X-Request-Id` ⇒ Rack/Rails. `Server: Puma`, `Phusion Passenger`, `WEBrick`,
  `thin`. `X-Powered-By` rarely set. `ETag`/`Cache-Control` Rails-style.
- **Error pages**: prod ⇒ generic "We're sorry, but something went wrong." (500)
  / "The page you were looking for doesn't exist." (404). **Dev mode** ⇒ a full
  Rails stack trace with source, gem versions, and `Rails.root` — high-severity
  info leak; capture with `http_flow_body`. Sinatra 404 ⇒ "Sinatra doesn't know
  this ditty.".
- **Dev/debug routes** (should never be exposed in prod): `/rails/info/routes`
  (full route map), `/rails/info/properties` (Ruby/Rails versions, gems),
  `/rails/mailers`, the better_errors console (`__better_errors`), `/sidekiq`,
  `/letter_opener`. A 200 on any ⇒ finding.
- **Forced-browse common paths** in ONE `http_fuzz` (`url:"http://host/FUZZ"`,
  `match_status:200`): `payloads:["rails/info/routes","rails/info/properties",
  "sidekiq","assets","config/database.yml",".git/config","Gemfile","Gemfile.lock",
  "config/secrets.yml","config/master.key","public/500.html","robots.txt"]`. Each
  matched row is a finding (config/secret/source disclosure).

Record: framework (Rails/Sinatra) + version, Ruby version, app server, dev-mode
exposure, and any leaked config/secret file.
Evidence: the version banner / dev trace / exposed file body.
Remediation: run `RAILS_ENV=production`, set `config.consider_all_requests_local
= false`, gate `/sidekiq` and `web-console` behind auth (or drop the gem in
prod), and keep `master.key`/`secrets.yml`/`.git` out of the docroot.
