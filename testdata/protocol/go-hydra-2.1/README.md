# Go dispatcher on Hydra 2.1: protocol captures

Recorded on 2026-11-03 by `make capture-go` in hydra-dev: `tools/recorder`
sat in front of the Go dispatcher (commit `4ff304d`, fallback mode, in-memory
state) and between it and the admin API of Hydra 2.1.2. The scenarios were
played by `examples/hydra-dev/e2e -into testdata/protocol/go-hydra-2.1`, the
browser through the real login apps: hydra-sql-go and hydra-oidc-go on the
v2 paths, hydra-passwordless on the v1 aliases. All passed, claims of the
final `id_token` included.

They attest what the Symfony captures cannot: the behaviour proper to the Go
dispatcher, on a real Hydra with the real apps (`Table de transitions.md` of
hydra-dev cites them as `go 04:0075`). Nothing reads them by name yet.

## Files

As in `../symfony-hydra-2.1/README.md`: one exchange per file, legs `front`
(Caddy to the dispatcher: the browser on the pages, the apps on the emulated
API) and `hydra` (the dispatcher to Hydra's admin API), `seq` unique across
the directories of this run. The e2e's own calls (Hydra's admin to find the
client and to read a login request, the token endpoint, fake-smtp) do not go
through the recorder.

## Scenarios

Hydra calls by scenario, in the order made; emulated: the apps' calls to the
emulated API.

| Directory | Path | Hydra | Emulated |
| --- | --- | --- | --- |
| `01-first-login-hydra-oidc` | oidc (alice, through the test IdP); Hydra consent skip. | 4: login, login accept, consent, consent accept | 4 |
| `02-first-login-hydra-sql` | sql; Hydra consent skip. | 4 | 5 |
| `03-first-login-hydra-sql-2fa` | sql-2fa, the code read in fake-smtp; Hydra consent skip. | 5: one more read of the login request, to pass to step 2 (BCL-8) | 11 |
| `04-second-login` | sql twice in the same browser. The second time Hydra asks to skip the login (`0066`), the dispatcher replays the flow: choice page, app's form, subject compared at the final accept, equal (FIN-2, `0075`). | 4 + 4 | 10 |
| `05-second-login-other-subject` | As `04`, test3@test.com signing in the second time: login reject `login_required` (`0103`), page E1003 (FIN-3). | 4 + 2 | 10 |
| `06-prompt-consent-accept` | sql, `prompt=consent`: the consent screen (`0115`), accepted (`0117`). | 5: the POST reads the consent request again (B3) | 5 |
| `07-prompt-consent-reject` | As `06`, refused (`0133`): consent reject `access_denied` (`0135`). | 5 | 5 |
| `08-back-to-choice` | sql chosen, the choice form posted again from the history with sql-2fa (POS-4, `0140`), the choice page reloaded (ENT-3, `0142`), oidc chosen. | 4 | 6 |
| `09-back-to-sql-2fa` | `prompt=consent`; sql chosen, back to the choice from the history, sql-2fa chosen; the consent screen accepted. Symfony's `27`. | 6 | 12 |

The Hydra calls are those of the table of B3 (`Plan phase 1.md`, P5): 4 for
one step, 5 for two, one more for the consent screen.

## Compared with Symfony

Same paths in the Symfony captures: `12` (`02`), `14` (`03`), `07` (`01`,
after a retry), `25` (`06`), `27` (`09`). The calls the apps make to the
emulated API, and their answers, differ by the deviations the phase 1 plan
assumes, and by nothing else:

- `x_dispatcher_restart_url` added to the login requests;
- the consent request of a step carries the `context` of its login accept
  (A2: hydra-oidc's claims, hydra-sql's email and names) and
  `x_dispatcher_claims`;
- `redirect_to` and the resumption URLs in `ref` form (`/oauth2/auth?ref=`);
- the final `id_token` keeps hydra-sql's email in sql-2fa, and hydra-oidc's
  claims in oidc, which Symfony lost.

Hydra calls: 4 where Symfony made 13 (sql), 5 for 21 (sql-2fa), 4 for 17
(oidc after a retry).

## Data

As in the Symfony captures, the only personal data are hydra-dev's seed
accounts: alice, test2@test.com, test3@test.com. No secret: the forms of the
apps, the IdP and the token endpoint are not behind the recorder.
