# Hydra's answers to unknown, handled, refused and expired requests

Recorded on 2026-10-29 by `tools/flowfixtures -errors` against throwaway
Hydras (`DSN=memory`, `TTL_LOGIN_CONSENT_REQUEST=5s`) of the versions the
dispatcher reads: one directory per version, named after what Hydra's
`/version` reports. The command is at the top of `tools/flowfixtures/main.go`;
rerun it for each Hydra release the dispatcher supports. The `login_skip_forget*`
and `consent_after_skip*` cases were added on 2026-11-04 (review R19, P8), from
a run without `-ttl` whose other files were left as they were.

`TestRecordedHydraAnswers` serves every admin API answer to the client: a
4xx must be a `RequestError` carrying Hydra's body as sent (a 410 its
`redirect_to`), a 2xx a success.

## Files

One exchange per file: `request` (`method`, `uri` with the challenge left
out, `body`) and `response` (`status`, `content_type`, `body`; `location` for
a redirect, with only Hydra's error parameters kept). The `*_verifier*`
cases are a browser on Hydra's public port, not the admin API: the test
skips them.

No secret beyond what hydra-dev already has: `secrets.system` is the dev
`youReallyNeedToChangeThis`, the database lived in memory and is gone.

## Cases and statuses

"Used" means Hydra has seen the verifier: the browser came back to it after
the accept.

| Case | What it does | 2.1.2 | 2.2.0 | 2.3.0 |
| --- | --- | --- | --- | --- |
| `login_unknown`, `consent_unknown`, `logout_unknown` | 32 zeros as challenge | 404 | 404 | 404 |
| `login_tampered`, `consent_tampered` | one character changed in a real challenge | 404 | 404 | 404 |
| `login_used` | GET a login request accepted and used | 410 | 200 | 200 |
| `login_accept_used`, `login_reject_used` | accept it again, reject it | 409 | 200 | 200 |
| `login_verifier_replayed` | follow the verifier of that second accept | — | 302 to consent | 302 to consent |
| `consent_accepted`, `consent_accept_accepted` | GET, accept again a consent accepted, verifier unused | 200 | 200 | 200 |
| `consent_used` | GET it once used | 410 | 200 | 200 |
| `consent_accept_used`, `consent_reject_used` | accept it again, reject it | 409 | 200 | 200 |
| `consent_verifier_replayed` | follow the verifier of the second accept | 303 `invalid_request` | 303 `access_denied`, "consent verifier has already been used" | same as 2.2 |
| `login_skip` | GET the next login, the session remembered | 200, `skip: true` | 200, `skip: true` | 200, `skip: true` |
| `login_other_subject` | accept that skip with another subject | 400 | 200 | 200 |
| `login_other_subject_verifier` | follow its verifier | — | 302 to a new login | 302 to a new login |
| `login_skip_forget` | accept a skip with `remember: false` | 200 | 200 | 200 |
| `login_skip_forget_verifier` | follow its verifier | 302 to consent | 302 to consent | 302 to consent |
| `consent_after_skip` | GET the consent of a skip accepted with a `context`, an `acr` and an `amr` | 200, the three as sent | 200, the same | 200, the same |
| `consent_after_skip_no_amr` | the same, accepted without `acr` nor `amr` | 200, `acr: ""`, `amr: []` | 200, the same | 200, the same |
| `login_bad_body` | `subject` as a number | 400 | 400 | 400 |
| `logout_handled`, `logout_accept_again` | GET, accept again an accepted logout | 200 | 200 | 200 |
| `login_expired`, `login_expired_accept` | GET, accept a pending login request past its lifetime, from a new browser | 200 | 401 `request_unauthorized` | 401 |
| `consent_expired`, `consent_expired_accept` | the same for a consent, of another subject than the remembered one | 200 | 401 | 401 |
| `login_expired_verifier`, `consent_expired_verifier` | follow the verifier of that accept | 303 `request_unauthorized`, "request has expired" | — | — |

## What it means for the dispatcher

- From Hydra 2.2, the admin API no longer tells a handled login or consent
  from a pending one: the challenge is the flow, and Hydra stores nothing for
  it until the consent verifier comes back. A second accept succeeds; only the consent verifier is refused at the
  browser's second pass, and the client gets `access_denied`. A double
  submission or a step back is the dispatcher's to absorb, from its own
  state: Hydra's 410 exists in 2.1 only.
- A skip accepted with `remember: false` succeeds, and so does its verifier:
  Hydra's accept handler sets `remember` itself on a skip
  (`consent/handler.go`), so the dispatcher sends the settings' value as it
  is. The consent request of a skip carries the `context`, `acr` and `amr` of
  the accept as sent, an `amr` left out as `[]`, and the login request's
  `request_url`: what the `x_dispatcher_skip` marker is computed on.
- A skip accepted with another subject fails in 2.1 (400). From 2.2 the
  accept succeeds and Hydra silently starts a new login: without its own
  subject check (E1003), the dispatcher would loop.
- Hydra 2.1 reads and accepts an expired login or consent request on the
  admin API, then refuses its verifier: the client gets
  `request_unauthorized`, "The login request has expired". From 2.2, the
  admin API itself answers 401 `request_unauthorized`. In every version the
  dispatcher's flow must end before Hydra's `ttl.login_consent_request`: on
  2.1, past it, the user goes through every step to an error at the client.
- A logout request stays readable and acceptable once accepted, in every
  version.
