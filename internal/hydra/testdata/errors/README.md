# Hydra's answers to unknown, handled, refused and expired requests

Recorded on 2026-10-29 by `tools/flowfixtures -errors` against throwaway
Hydras (`DSN=memory`, `TTL_LOGIN_CONSENT_REQUEST=5s`) of the versions the
dispatcher reads: one directory per version, named after what Hydra's
`/version` reports. The command is at the top of `tools/flowfixtures/main.go`;
rerun it for each Hydra release the dispatcher supports. The `login_skip_forget*`
and `consent_after_skip*` cases were added on 2026-11-04 (review R19, P8), from
a run without `-ttl` whose other files were left as they were; the `logout_*`
cases but the first three of the table, and `consent_after_logout`, on 2026-11-05
(P9), with `-secret` and `-post-logout`, the other files left as they were too.

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
`youReallyNeedToChangeThis`, the database lived in memory and is gone. The tool
redeems an `id_token` for the logout's cases, and writes `<id_token>` in its
place; the iframes of a front-channel page keep `<iss>` and `<sid>`.

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
| `logout_handled`, `logout_accept_again` | GET, accept again an accepted logout (HLO-1, HLO-3) | 200 | 200 | 200 |
| `logout_request` | GET a logout request without a hint (HLO-7) | 200, `rp_initiated: false`, `client: null` | the same | the same, `requested_at`, `expires_at` |
| `logout_request_hint` | with `id_token_hint`, `post_logout_redirect_uri`, `state` | 200, `rp_initiated: true`, the whole client without its secret, the whole query in `request_url` | the same | the same |
| `logout_request_posted` | the same, by a POST | 200, `request_url` without query | the same | the same |
| `logout_reject_accepted` | reject an accepted logout (HLO-5) | 204 | 204 | 204 |
| `logout_reject_accepted_verifier` | follow its verifier, which is refused: the session lives | 302 to `urls.error`, `Not Found` | the same | the same |
| `logout_reject`, `logout_reject_again` | reject a logout, twice (HLO-5) | 204 | 204 | 204 |
| `logout_rejected` | GET it | 404 | 404 | 404 |
| `logout_accept_rejected` | accept it all the same: the accept erases the reject | 200 | 200 | 200 |
| `logout_accept_rejected_verifier` | follow its verifier, which ends the session | 200, front-channel | the same | the same |
| `logout_verifier`, `logout_verifier_first` | follow the verifier (HLO-2) | 200, front-channel | the same | the same |
| `logout_after_verifier` | GET it once followed (HLO-3) | 410, relative `redirect_to` | the same | the same |
| `logout_accept_after_verifier`, `logout_reject_after_verifier` | accept it, reject it (HLO-4) | 200, the same verifier; 204 | the same | the same |
| `logout_after_reject`, `logout_accept_after_reject` | GET it, accept it again | 404; 200 | the same | the same |
| `logout_verifier_replayed` | follow the verifier again (HLO-6) | 302 to `urls.error`, `Not Found` | 302 to `urls.post_logout_redirect` | the same as 2.2 |
| `consent_after_logout` | GET the consent of a flow in progress as the logout ends (HLO-15) | 200, `login_session_id` empty | 200, `login_session_id` kept | the same as 2.2 |
| `logout_expired`, `logout_expired_accept` | GET, accept a logout past `ttl.login_consent_request` (HLO-10) | 200 | 200 | 200 |
| `logout_expired_verifier` | follow its verifier | 200, front-channel | the same | 302 to `urls.error`, `request_unauthorized`: the session lives |
| `logout_expired_used` | GET it once followed | 410 | 410 | 410 |
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
  version. The accept ends nothing: only the browser's visit of the verifier
  does (HLO-1, HLO-2), which is why the verifier comes last and a note of logout
  replaces the remember cookie at the start of the chain (Q45).
- A reject answers 204 in every state, and a reject after an accept makes the
  verifier refused, the session alive; an accept erases a reject (HLO-5): the
  dispatcher reads a logout request again before it rejects (Q50).
- From 2.3, past `expires_at`, the read and the accept still answer 200 and only
  the verifier is refused (HLO-10): the dispatcher reads `expires_at` first (Q52).
- What a browser does to the logout, which an admin answer does not show, is
  played against throwaway Hydras by `logout_integration_test.go`.
