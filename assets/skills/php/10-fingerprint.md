# Fingerprint a PHP stack

Confirm PHP and identify framework/CMS/version to choose targeted tests.

Gather signals with `browser_navigate`, `browser_get_cookies`, `scan_passive`
(its `headers` section), and `http_request`:

- **Cookies**: `PHPSESSID` ⇒ PHP. `laravel_session` / `XSRF-TOKEN` ⇒ Laravel.
  `symfony` ⇒ Symfony. `ci_session` ⇒ CodeIgniter. `wordpress_*` / `wp-settings`
  ⇒ WordPress.
- **Headers**: `X-Powered-By: PHP/x.y` (leaks the version — finding), `Server`,
  cookie flags on `Set-Cookie`.
- **Paths/extensions**: `.php` URLs, `/wp-login.php`, `/wp-admin/`,
  `/administrator/` (Joomla), `/index.php?option=com_` (Joomla).
- **Bodies**: `<meta name="generator">`, framework error/debug pages
  (`Whoops`, Symfony profiler, `Warning: ... on line`) — read with
  `http_flow_body` on error responses.
- **Probe common files** in ONE `http_fuzz` forced-browse instead of one call
  each: `url:"http://host/FUZZ"`, `match_status:200`, `payloads:["phpinfo.php",
  "info.php",".env","composer.json","config.php.bak",".git/config",
  "server-status"]`. Each `matched:true` row (or a 200) is a finding.

Record: PHP version, framework/CMS, any exposed debug/info/config file (each a
finding), and `X-Powered-By` disclosure (low severity — remove it).
