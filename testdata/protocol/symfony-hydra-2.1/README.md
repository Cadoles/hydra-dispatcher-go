# Symfony dispatcher on Hydra 2.1: protocol captures

Recorded by `make capture` in hydra-dev: `tools/recorder` sat in front of
the Symfony `hydra-dispatcher` and between it and the admin API of Hydra
2.1.2. They freeze what Symfony does today: the reference for behaviour
(extensions, `[]`, `{}` and `null`, aggregation of the steps, error answers),
not for the shape the Go dispatcher serves (Symfony serves the v1 paths and
Hydra 2.1 models).

- `01` to `15`, on 2026-10-26: played by hand in a browser, with the real
  login apps, Symfony in `APP_ENV=dev`.
- `16` to `25`, on 2026-10-29: played by `tools/scenarios`, Symfony in
  `APP_ENV=prod` (`CAPTURE_APP_ENV=prod CAPTURE_APP_DEBUG=0 make capture`),
  so that errors are Symfony's answers, not its debug page. The tool is the
  browser and the login apps: their calls to the emulated API carry the
  bodies hydra-sql-go and hydra-passwordless send (taken from `14`), but come
  from the host through Caddy.
- `26`, on 2026-11-02: Symfony in `APP_ENV=prod`, the capture layer up for
  `recorder`, `caddy` and `hydra-dispatcher` only. Caddy replaces the
  `X-Forwarded-For` of a request from the host, which then always comes from
  an allowed private address: the four calls of `21` were sent instead from a
  throwaway container on the `backend` network straight to the recorder's
  front leg, with `X-Forwarded-For: 203.0.113.10` (a documentation address,
  outside `HYDRA_ADMIN_AUTHORIZED_HOSTS`), which Symfony's `TRUSTED_PROXIES`
  take as the client:

  ```sh
  docker run --rm --network hydra-dev_backend --entrypoint sh curlimages/curl:8.11.1 -c '
    curl -H "Host: dispatcher.hydra.test" -H "X-Forwarded-For: 203.0.113.10" \
      "http://recorder:8080/oauth2/auth/requests/login?login_challenge=<32 hex>"
    # then PUT login/accept, GET consent, PUT consent/accept, bodies of 21'
  ```

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
| `16-consent-reject-first-step` | sql: the app accepts the login, then rejects its consent (hydra-sql-go's deny button). | |
| `17-consent-reject-second-step` | sql-2fa: step 1 accepted, hydra-passwordless accepts its login and rejects its consent. | |
| `18-login-reject-first-step` | sql: the app rejects the login. | |
| `19-login-reject-second-step` | sql-2fa: step 1 accepted, the second app rejects its login. | |
| `20-accept-twice` | sql: each accept of the step sent twice; stops at the dispatcher's consent screen. | |
| `21-unknown-step-challenge` | The four reads and accepts of the emulated API with a well-formed challenge no flow issued. | |
| `22-malformed-challenge` | `not-a-challenge` on the emulated API, `/`, `/oauth2/auth` and `/consent`. | |
| `23-csrf-mismatch` | The choice posted with a `dispatcher_flow_csrf` cookie the page did not set. | |
| `24-back-after-final-accept` | sql up to the dispatcher's consent screen, then back to `/oauth2/auth` and `/` with Hydra's login challenge. | |
| `25-back-after-the-end` | sql completed (consent screen accepted), then back to `/oauth2/auth`, `/` and `/consent`. | |
| `26-allowlist-refusal` | The four calls of `21`, from an address outside the emulated API's allowlist. | |

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

Artifacts of `tools/scenarios` (`16` to `25`): `User-Agent`
`hydra-dispatcher-go/tools/scenarios` on the browser's requests,
`Go-http-client/1.1` on the apps' calls; the apps' calls come from the host
(`X-Forwarded-For` of the host's gateway, not a login app's address); one
read of each login and consent request, where hydra-sql-go makes two and
hydra-passwordless three.

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

## What `16` to `25` show

- **A reject by an app** (login or consent, first or second step) reaches
  Hydra as a login reject, with the app's body. Hydra answers 200; Symfony
  answers the app **410** with Hydra's `redirect_to`, not Hydra's 200.
- **An unknown step challenge**: **404**
  `{"error":"missing_session_error","error_description":"Could not find session metadata in cache","status_code":404}`
  on all four calls, no call to Hydra.
- **A malformed challenge**: 404
  `{"error":"invalid_request","error_description":"request_failed","status_code":404,"trace_id":…}`
  on the emulated API, the HTML error page on the pages; no call to Hydra.
- **An accept sent twice**: 200 both times, with the same `redirect_to`.
- **A flow CSRF cookie mismatch** on the choice: the choice page again,
  without a message.
- **Back to `/oauth2/auth` or `/` after the final accept**: Symfony reads the
  login request, Hydra answers 410, Symfony redirects (302) to Hydra's
  `redirect_to`, which starts a new authorization.
- **Back to `/consent` after the end**: Hydra answers 410 to the consent
  request, Symfony answers with its error page in **500**.
- In `APP_ENV=prod`, the consent screen's title is the untranslated key
  `view.consent.title`.

## What `26` shows

- **A call from outside the allowlist**: **500**
  `{"error":"server_error","error_description":"request_failed","status_code":500,"trace_id":…}`
  on all four calls, not the 403 of Symfony's `doc/api.md`, and no call to
  Hydra. The `access_control` of `^/oauth2/auth/requests` raises an
  `AccessDeniedException` (403, "The user doesn't have ROLE_NO_ACCESS"),
  which the emulated API's exception handling answers as any other error.
- Artifacts: `User-Agent` `curl/8.11.1`; `X-Forwarded-For` as sent, the
  upstream receiving the throwaway container's address after it.

## Not captured yet

Needed by the contract tests of phase 1, most useful first:

1. An expired step challenge (`challenge_ttl` lowered for the capture).
2. Consent after a login skip, with non-empty claims (sql or sql-2fa).
3. sql-2fa with the consent screen accepted, complete and without going back,
   to replace `05` and `09`.
4. Hydra login skip without a valid Symfony session: the choice page.
5. Logout initiated by the client: `rp_initiated: true`, `client` set.
6. Variants of `/` (auto-selection, preferred-app `acr_values`,
   `unmet_authentication_requirements`, `metadata.dispatcher.flows`,
   `ui_locales`) and of `/consent` (`skip_consent`, `consent_auto_accept`).
7. hydra-passwordless's calls to the emulated logout endpoints (404 today).

Capture the error scenarios with `APP_ENV=prod`: in dev, Symfony answers with
its debug exception page. Hydra's own answers, for 2.1, 2.2 and 2.3, are in
`internal/hydra/testdata/errors`.
