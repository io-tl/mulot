# Race conditions (limit overrun / TOCTOU) — capability

Any action meant to happen ONCE or be capped (coupon/voucher redeem, wallet
transfer, invite-code use, free-trial signup, vote/like, failed-login counter,
unique-username registration) is a race-condition candidate if the check and
the write aren't atomic. `http_fuzz` is SEQUENTIAL (one request at a time) and
cannot win a race — use `browser_evaluate_js` concurrency instead.

1. **Find the action**: a form/endpoint with an explicit limit or a "can only
   be done once" semantic (`browser_get_form_fields`, `http_history`).
2. **Capture the exact request** (method, url, body) from `http_history`.
3. **Fire it N times AT ONCE, in-page**, same-origin so the session cookie
   rides along automatically: `browser_evaluate_js` with
   `(async()=>{const r=await Promise.all([...Array(20)].map(()=>fetch(url,
   {method,headers,body,credentials:'include'})));return await Promise.all(
   r.map(x=>x.status));})()`
   — all 20 requests leave nearly simultaneously (no round-trip between them),
   unlike a loop of `http_request` calls.
4. **Cross-origin or header-only auth** (no browser session to piggyback on):
   fire several `http_request` calls back-to-back as fast as you can issue
   tool calls — weaker (network latency reintroduces sequencing) but still
   worth trying when in-page `fetch` can't carry the right headers/cookies.
5. **Confirm impact on STATE, not status codes**: re-fetch the resource
   afterward (balance, redeemed-coupon count, number of accounts created) — if
   more than one concurrent request succeeded where only one should have, the
   race is proven. A batch of `200`s alone is not proof; re-read the ledger.

Evidence: the state after the burst (e.g. balance credited twice, a coupon
redeemed by N sessions, two accounts created from one invite) — capture the
request set + the post-burst re-fetch showing the overrun.
Remediation: atomic DB operations (`UPDATE ... WHERE balance>=amount` /
row-level locking / unique constraints) instead of read-then-write; idempotency
keys on state-changing endpoints; short-lived locks around the critical section.
