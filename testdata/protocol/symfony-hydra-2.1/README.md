# Symfony dispatcher on Hydra 2.1: protocol captures

Recorded on 2026-10-26 by `make capture` in hydra-dev: `tools/recorder` sat in
front of the Symfony `hydra-dispatcher` and between it and the admin API of
Hydra 2.1.2, and the scenarios were played by hand in a browser. They freeze
what Symfony does today: the reference for behaviour (extensions, `[]`, `{}`
and `null`, aggregation of the steps), not for the shape the Go dispatcher
serves (Symfony serves the v1 paths and Hydra 2.1 models).

`internal/hydra` tests read some of these files by name: renaming or removing
a directory means updating `emulated_test.go` and `client_test.go`.

## Files

- One exchange per file, `NNNN-<leg>-<METHOD>-<path>.json`:
  `seq`, `leg`, `time`, `duration_ms`, then `request` (`method`, `host`, `uri`,
  `headers`, `body`) and `response` (`status`, `headers`, `body`).
- `front`: Caddy to the dispatcher. The browser on `/`, `/oauth2/auth`,
  `/consent`, `/logout`, and the login apps on the emulated API
  (`/oauth2/auth/requests/...`).
- `hydra`: the dispatcher to Hydra's admin API (`/admin/oauth2/auth/requests/...`).
- `seq` follows arrival across both legs: the Hydra calls a front request
  caused come right after it. Numbering runs from `01` to `09`, then starts
  again at `0001` in `11` (second session): it is unique within a directory
  only.
- JSON bodies are kept as received (re-indented); any other body (HTML page,
  form) is a JSON string.
- The choice form posts the flow id: `0` oidc, `1` sql, `2` sql-2fa (sql, then
  hydra-passwordless).
- "Hydra consent skip" below means Hydra answered `skip: true`: it remembered
  an earlier consent of the subject for this client.

## Scenarios

| Directory | Path | Needs |
| --- | --- | --- |
| `01-skip`, `02-skip` | alice (hydra-oidc): login skip honoured from Symfony's session, Hydra consent skip. The claims sent at consent are `{}`: hydra-oidc gives none. | an earlier login of alice in the same browser, not captured |
| `03`, `06`, `08`, `11`, `13-logout` | Logout from Hydra's `/oauth2/sessions/logout`, accepted at once: `rp_initiated: false`, `client: null`. | a session |
| `05-sql-2fa-consent-screen-accept-INCOMPLETE-…` | sql chosen, back to the choice with the browser's back button (no new `GET /`), sql-2fa chosen; the dispatcher's consent screen accepted. The only capture of that screen accepted. | |
| `07-oidc-after-sql-retry-consent-skipped` | sql chosen, back the same way, oidc chosen; Hydra consent skip. | |
| `09-sql-2fa-consent-skipped-INCOMPLETE-…` | sql-2fa, Hydra consent skip. Superseded by `14`. | |
| `12-sql-consent-skipped` | sql, single step; Hydra consent skip. 13 Hydra calls, 10 of them reads of the login request. | |
| `14-sql-2fa-consent-skipped` | sql-2fa, with hydra-passwordless's calls; Hydra consent skip. 21 Hydra calls, 18 reads. hydra-passwordless sends `"email": null`, which overwrites sql's email in the final `id_token`. | |
| `15-login-skip-consent-screen-reject` | Login skip, `prompt=consent`, consent screen refused: `consent/reject` with `{"error":"access_denied"}`. | the session of `14` |

`INCOMPLETE`: hydra-passwordless hangs up as soon as it has decoded the JSON,
and the recorder of the time lost those exchanges. Its calls are missing
(`0052`, `0054`, `0056`, `0058`, `0062`, `0064` in `05`; `0132`, `0134`,
`0136`, `0138`, `0142`, `0144` in `09`); the Hydra reads Symfony made for them
remain.

## Comparing

Capture artifacts, never compared:

- `request.host` on the `hydra` leg: `recorder:8081`, the Host Hydra received.
- Request `X-Forwarded-For`: the upstream received one more hop, Caddy's
  address. No effect on Symfony, whose `TRUSTED_PROXIES` covers the private
  networks.
- Request `Accept-Encoding`: the recorder drops it, so Go's transport asks for
  gzip itself and decompresses. The upstream still compressed (FrankenPHP's
  `encode`), and the recorded responses lack `Content-Encoding` and
  `Content-Length` but keep `Vary: Accept-Encoding`.
- Symfony ran with `APP_ENV=dev`: `X-Debug-Token*` headers, `sf_redirect` and
  `main_*_profile_token` cookies, the web debug toolbar in HTML pages,
  `Baggage` and `Sentry-Trace` on the Hydra calls.
- Values of a run: `Date`, `X-Trace-Id`, challenges, verifiers, session ids,
  cookies, CSRF tokens, `state`, `nonce`.

Symfony behaviour the Go dispatcher does not reproduce, on purpose: at the
first step the emulated login request has `"subject": null` (Go: `""`) and
`"x_dispatcher_claims": []` (Go: `{}`); Go omits the fields Symfony serves as
`null`; Symfony sends `"context": []` in its final login accept to Hydra.

## Data

The only personal data are hydra-dev's seed accounts: alice, alice@example.com,
Alice Anderson (`files/apps/oidc/seed.yaml`) and test2@test.com, Isabelle
Durand (`files/postgres/init-db.d/fill_lasql.sql`). Sessions, CSRF tokens and
verifiers belonged to a dev stack since reset. There is no secret: no client
secret, token, JWT or password, as the login apps' own forms are not behind
the recorder. Never capture against a real identity provider or real accounts.

## Not captured yet

Needed by the contract tests of phase 1, most useful first:

1. `PUT consent/reject` from an app (the deny button of hydra-sql-go's consent
   screen), at the first and the second step.
2. `PUT login/reject` from an app: no Go login app calls it, so curl it from
   the backend network.
3. Stale, unknown and expired challenges: back to `/oauth2/auth` after the
   final accept, an unknown step challenge on the emulated API, a malformed
   challenge (404), `challenge_ttl` lowered for the capture, an accept sent
   twice (Hydra's 410).
4. Consent after a login skip, with non-empty claims (sql or sql-2fa).
5. sql-2fa with the consent screen accepted, complete and without going back,
   to replace `05` and `09`.
6. Hydra login skip without a valid Symfony session (another browser
   profile): the choice page.
7. Logout initiated by the client: `rp_initiated: true`, `client` set.
8. Variants of `/` (auto-selection, preferred-app `acr_values`,
   `unmet_authentication_requirements`, `metadata.dispatcher.flows`,
   `ui_locales`) and of `/consent` (`skip_consent`, `consent_auto_accept`).
9. Refusal by the emulated API's allowlist (403), flow CSRF cookie mismatch on
   `/`.
10. hydra-passwordless's calls to the emulated logout endpoints (404 today).

Capture the error scenarios with `APP_ENV=prod`: in dev, Symfony answers with
its debug exception page.
