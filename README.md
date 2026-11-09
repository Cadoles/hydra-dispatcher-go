# hydra-dispatcher-go

The single login app [Ory Hydra](https://github.com/ory/hydra) talks to. It
chains several real login apps into a flow (MFA, identity provider choice,
protocol choice) by replaying Hydra's login/consent protocol towards each of
them.

Go rewrite of the Symfony dispatcher (repository `hydra-dispatcher`). Work in
progress, phase 1 (plan and journal in `hydra-dev/conception`): the binary serves the pages (choice of
the flow, consent, errors, logout with its confirmation), the emulated admin API
the login apps call (v2 paths and v1 aliases), `/health` and `/ready`; it keeps its configuration in Postgres and the flows in
progress in memory, or in Redis (or Dragonfly) when `state.redis_dsn` is set, a
call bounded to 1 s and two attempts unless its URL says otherwise (`dial_timeout`,
`read_timeout`, `write_timeout`, `max_retries`).

## Commands

```
hydra-dispatcher serve [-config dispatcher.yaml]    run the HTTP server
hydra-dispatcher migrate [-config ...]              apply the database migrations
hydra-dispatcher migrate down [-config ...] [-yes]  roll back the last migration
hydra-dispatcher bootstrap [-config ...] [-force] [-dry-run] [-yes]
                                                    write the seed of the configuration file to the database
hydra-dispatcher healthcheck [-url ...]             probe /health of a local server (container HEALTHCHECK)
hydra-dispatcher theme check <dir>                  render the pages of a theme as serve does, one line by problem
hydra-dispatcher version                            print the version
```

`theme check` needs neither a configuration nor a database: it loads the
theme directory over the embedded theme and renders each page in each locale,
as `serve` does at its start with `ui.theme_dir`; it exits 1 on a problem.
With `ui.reload: true`, for the development of a theme, the pages read it again
when one of its files changed, and answer 500 with the error while it fails.

`-config` defaults to `$DISPATCHER_CONFIG`, which `healthcheck` reads too for
the `server.listen` to probe: in a container, give the file by the variable.

`bootstrap` creates what the database lacks from the `dispatcher:` block (the
seed); `-force` rewrites too what the database holds of it, and resets the
settings the seed sets to `~`. Neither deletes. `-dry-run` prints the changes
and writes nothing; in a terminal, `-force` prints them and asks, unless
`-yes`. The changes go to stdout alone, the log lines to stderr. `serve`
migrates at startup with `serve.migrate: true`, and
bootstraps with `serve.bootstrap: missing` or `force`, logging the changes.

An app's `receive_claims` names the claims of the previous steps it receives,
`[]` none. Without the key, a new app receives every claim and `-force` leaves
an existing one as it is; `~` gives every claim, to an app that has a list
too, with the warning `bootstrap.claims_widened`.

`migrate down` rolls back one migration, with the version that applied it,
before going back to the previous image; in a terminal it names the migration
and asks, unless `-yes`.

The audit log (`observability.audit.output`: `stdout`, beside the other two streams
under `log_type` `audit`, `file:<path>`, or `syslog`) is for a SIEM: authentications
that succeed or fail, skips, a subject that changes between steps, logouts, IP refusals,
with the full IP. Its subjects are an HMAC by `secrets.audit_key`, or without it by a
key derived from `secrets.challenge_key`, whose rotation then changes the pseudonyms;
`observability.audit.pseudonymize_subject: false` writes them in clear. Its lines go
through a bounded queue: an output that blocks, a syslog whose daemon reads no more,
loses lines, counted by `hydra_dispatcher_audit_dropped_total` and told by
`audit.dropped`, rather than hold the requests; the queue is emptied at the stop.

With `observability.sentry.dsn`, Sentry gets what demands an action: the pages E1000,
E1004 to E1007, a panic, an error line of the log, at most
`max_events_per_minute` by instance, grouped by code and operation. Never a subject,
a claim, a challenge, a cookie or a query string; the info and warn lines of a request are
its breadcrumbs, by name.

`observability.tracing` (or the standard `OTEL_*` variables, which win) exports traces
over OTLP, gRPC or HTTP: a span by request, named by its route, one by call to Hydra or a
webhook and by operation of the state store, a later request linked to the span that
created its flow. The `traceparent` of a proxy or a login app continues its trace; any
other client's is only a link. Off by default, at almost no cost. With
`observability.sentry.traces_sample_rate` above 0, the spans go to Sentry too.

An address that forges on the pages (a challenge no one issued, an invalid CSRF token)
gets 429 past `security.failure_rate_limit`, 20 a minute by default, for 5 minutes, in the
memory of each instance; IPv6 by /64. An expired challenge is authentic, and does not
count; nor does what an address does not choose: the calls of the emulated API, whose
challenge a login app takes from any browser, and what another site's page loads
(`Sec-Fetch-Dest` other than `document`). The choice page checks the last flow started from its
form, by the cookie `dispatcher_last_flow`, unless `ui.remember_last_flow: false`.

`serve` exposes `/metrics` (Prometheus, OpenMetrics when asked for), in the memory
of the instance, a scrape touching neither Redis nor the database, behind
`security.metrics_authorized_hosts`; or on a port of its own with
`observability.metrics.listen`, gone from the main one.

`serve` exposes `/health` (liveness) and `/ready`, the state of the instance:
200 once it serves, 503 while it drains. Its checks (Hydra, the database and the
state store, within 2 s, Redis by a `PING`) are in its body, in the log at each
change and in `hydra_dispatcher_ready_check_up`, without changing its status: a
dependency every instance shares would otherwise take them all out at once, where
Hydra down gives page E1004. A readiness probe needs a timeout over 2 s.

On SIGTERM, `serve` answers 503 on `/ready` for `server.drain_delay` (0 by
default; 5s under Kubernetes, with a `terminationGracePeriodSeconds` of at least
`drain_delay` + 10 s) while still serving, then lets the requests in flight end
for 6 s, cuts the others, and flushes traces and Sentry in 2 s at most: within
the 10 s of `docker stop` without a drain. A server that stops on its own, the
main one or that of `observability.metrics.listen`, stops the process. It reads the
configuration from the database at startup, then every 60 s. Logs are JSON
lines on stdout, `log_type` `app` or `access`, with the request's
`trace_id`; `log_level` applies to the application log only.

## Configuration

One YAML file (`internal/config`, example in
`internal/config/testdata/design-doc.yaml`) describes the infrastructure; its
`dispatcher:` block is the seed bootstrap writes to the database, in the
Symfony `dispatcher.yaml` format. Without `-config`, the defaults and the
environment are used.

- Every value accepts `${VAR}` and `${VAR:-default}`.
- `DISPATCHER_<SECTION>_<KEY>` overrides any infrastructure key, e.g.
  `DISPATCHER_SERVER_BASE_URL`, `DISPATCHER_ADMIN_API_TOKEN_TTL=15m`,
  `DISPATCHER_SECURITY_ADMIN_AUTHORIZED_HOSTS=10.0.0.0/8,127.0.0.1`. The seed
  and `ui.csp_extra` are not reachable this way.
- Durations take `5s`, `30m`, `365d` or seconds (`900`); lists a YAML sequence
  or a comma-separated string; keys 32 bytes in hex or base64.
- Unknown keys are errors. Required: `server.base_url`,
  `server.trusted_proxies` (the reverse proxies' addresses only, `[]` when
  clients connect directly), `security.emulated_api_authorized_hosts` (the
  networks the login apps call from, `[]` closes the emulated API),
  `hydra.admin_url`, `store.dsn`, `secrets.cookie_key`,
  `secrets.challenge_key`.
- `server.base_url` is written as browsers send their `Origin`: scheme and
  host in lowercase, no default port, no user. A path in it is a prefix the
  reverse proxy removes before the dispatcher; the pages put it back before
  their URLs, and `server.cookie_path` must cover it.
- Every secret may come from a file instead, its key followed by `_file`:
  `secrets.cookie_key_file`, the other keys of `secrets` and their previous ones
  (one key per line), `store.dsn_file`, `state.redis_dsn_file`,
  `admin.api.private_key_file`, as `hydra.system_secrets_file`; the key and its file
  together are an error. A local program of the webhooks reads the environment of
  the dispatcher in `/proc/1/environ`: with one configured, a secret given by the
  environment is warned of.
- `store.dsn` loses the parameters of a Doctrine `DATABASE_URL`
  (`serverVersion`, `charset`…), which Postgres refuses, with a warning.

Until 1.0, the variables of the Symfony dispatcher are read in fallback, each
with a `config.warning` naming the key to set instead: a key takes one only
when neither the file nor a `DISPATCHER_*` variable sets it (defaults < Symfony
variables < file < `DISPATCHER_*`), and one a set key leaves aside is warned of
too. A variable the file references by `${VAR}` is the file's.

| Symfony | Key | |
| --- | --- | --- |
| `HYDRA_ADMIN_BASE_URL` | `hydra.admin_url` | |
| `HYDRA_HTTP_MAX_DURATION` | `hydra.timeout` | seconds |
| `BASE_URL`, `BASE_PATH`, `SERVER_NAME` | `server.base_url` | an absolute `BASE_URL`; else an absolute `BASE_PATH`; else `SERVER_NAME`, one `http(s)://` address, then the path `BASE_PATH` |
| `COOKIE_PATH` | `server.cookie_path` | |
| `TRUSTED_PROXIES` | `server.trusted_proxies` | `REMOTE_ADDR` dropped, refused alone; `PRIVATE_SUBNETS` the private networks |
| `HYDRA_ADMIN_AUTHORIZED_HOSTS` | `security.admin_authorized_hosts` | not `security.emulated_api_authorized_hosts`, required |
| `REDIS_DSN` | `state.redis_dsn` | one server, no option in the query |
| `DATABASE_URL` | `store.dsn` | |
| `OAUTH2_PRIVATE_KEY`, `OAUTH2_PUBLIC_KEY`, `OAUTH2_TOKEN_TTL` | `admin.api.*` | |
| `ADMIN_UI_ENABLED` | `admin.ui.enabled` | |
| `WEBHOOK_PROCESS_TIMEOUT` | `webhooks.process_timeout` | seconds |
| `SENTRY_DSN`, `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE` | `observability.sentry.*` | `sample_rate` 1 by default, not 0.25 |

`OAUTH2_ADMIN_CLIENT_*` (no implicit client: `dispatcher.oauth2_clients`),
`DEFAULT_LOCALE` and `APP_LOCALES` (settings of the seed) are not read; one
warning lists those without use here, FrankenPHP's among them.

## Webhooks

The settings `login_accept_webhook_url` and `consent_accept_webhook_url` name a
webhook called before the login accept (the final one, or a skip's) and before
the consent accept. Empty, none. Three forms, those of the Symfony dispatcher:
an `http(s)://` URL; a `file://` URL, the program run without arguments; or,
without a scheme, a command line split on spaces (double quotes hold spaces),
run without a shell.

**They must be idempotent.** A skip calls them again on what the remember cookie
keeps, which already went through them: a webhook that adds a group or a prefix
would add it at each skip. A reload after a failure calls them again too.

Over HTTP, a `POST` of JSON, in 5 s at most, with no proxy from the environment
and no redirect followed; an idle connection closed after 30 s, as towards Hydra,
under the idle timeout of common balancers, and over HTTP/2 a silent one pinged; `webhooks.ca_file` replaces the system's authorities.
`secrets.webhook_signing_key` is required with a URL, and `tls.allow_http` with
an `http://` one. Each call is signed, and a receiver must refuse a signature
that does not verify, or a timestamp over 5 minutes old:

```
X-Dispatcher-Timestamp: <Unix seconds>
X-Dispatcher-Signature: hex(HMAC-SHA256(key, timestamp + "." + body))
```

A program gets the payload and a newline on stdin, answers on stdout and exits 0,
within `webhooks.process_timeout`, at most `webhooks.max_processes` at a time. It runs
in a process group of its own, killed at its end as at the timeout: what it leaves
behind dies with it, a daemon included. In the image, `tini` is PID 1 and reaps the
orphans; an image built from it without `tini` takes `docker run --init`. It
sees `PATH`, `HOME`, `LANG`, `LC_ALL` and `TZ` of the environment, nothing else,
and what it writes on stderr goes nowhere. Nothing on stdout changes nothing.

The login webhook receives `challenge` (Hydra's, 1.5 KB from Hydra 2.2 on: do not
check its format), `subject`, `acr`, `amr`, `context`, `remember`, `remember_for`,
`browser` (`ip`, `user-agent`) and `client` (`client_id`, `client_name`, `logo_uri`,
`tos_uri`, `policy_uri`); it may answer `subject`, `acr`, `amr`, `context`, `remember`
and `remember_for`. The consent webhook receives `challenge`, `subject`, `acr`, `amr`,
`context` (the login's), `grant_scope`, `grant_access_token_audience`, `access_token`,
`id_token`, `browser` and `client`; it may answer `grant_scope`,
`grant_access_token_audience`, `access_token` and `id_token`. Scopes or audiences it
widens end the skip of the next login, which needs the same ones.

What an answer leaves out stays as it was; a member the dispatcher does not know is
ignored; `null` drops `acr`, `remember` or `remember_for`, and empties `context`; `[]`
stands for an empty `context`, `access_token` or `id_token`, or an empty answer. Over
HTTP, 200 and `application/json`. Anything else (another status, a wrong type, a
non-empty list, an empty `subject`) stops the authentication: page E1006, nothing
rejected at Hydra, a reload calling the webhook again. The log line `webhook.failed`
names the host or the program, the status or the exit code, and the member at fault,
never a value.

## Development

Go 1.26 minimum; the `toolchain` directive in `go.mod` selects the build
toolchain. Lint tools are pinned as `tool` dependencies in `go.mod`.

```sh
go build ./...
go vet ./...
go tool staticcheck ./...
go tool govulncheck ./...
go test -race ./...
docker build --build-arg VERSION=dev -t hydra-dispatcher-go .
```

The store's integration tests (tag `integration`) need a Postgres 17 built
with ICU, as the official images are, where they may create databases; the
tag without `DATABASE_URL` fails. Vet and staticcheck their files too:

```sh
docker run -d --rm --name dispatcher-pg -e POSTGRES_PASSWORD=dispatcher -p 127.0.0.1:55432:5432 postgres:17-alpine
DATABASE_URL='postgres://postgres:dispatcher@127.0.0.1:55432/postgres?sslmode=disable' \
  go test -race -tags integration ./internal/store/...
go vet -tags integration ./...
go tool staticcheck -tags integration ./...
```

The state store's integration tests (same tag) run the store's contract
against each server of `REDIS_URLS`, comma-separated: a Redis 7 and a
Dragonfly of hydra-dev's version, each in a throwaway container on a port of
its own, never the stack's; the tag without `REDIS_URLS` fails:

```sh
docker run -d --rm --name dispatcher-redis -p 127.0.0.1:56379:6379 redis:7-alpine
docker run -d --rm --name dispatcher-dragonfly -p 127.0.0.1:56380:6379 ghcr.io/dragonflydb/dragonfly:v1.34.1 --proactor_threads=2
REDIS_URLS='redis://127.0.0.1:56379/0,redis://127.0.0.1:56380/0' \
  go test -race -tags integration ./internal/state/...
```

`internal/hydra`'s integration test (same tag) plays what a browser does to
Hydra's logout, which no admin answer shows: the verifier, the back-channel, the
session cookie (the HLO lines of the transitions table). It needs a Hydra 2.1.2,
2.2.0 and 2.3.0 on Postgres, on ports of their own, never the stack's, given by
`HYDRA_URLS`, comma-separated, each `public|admin`, with
`urls.post_logout_redirect` and the short `id_token` lifetime below; and three more,
at the short request lifetime below, given by `HYDRA_SHORT_URLS`, for HLO-10.
`HYDRA_CALLBACK_HOST` is where they reach the test for the back-channel, the docker
bridge by default. The tag without those two fails. The CI does not run it: its
services cannot be given Hydra's command, nor migrate first:

```sh
docker run -d --rm --name hydra-pg -e POSTGRES_PASSWORD=hydra postgres:17-alpine
until docker exec hydra-pg pg_isready -U postgres -h 127.0.0.1; do sleep 1; done
PG=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' hydra-pg)
port=56444
for v in 2.1.2 2.2.0 2.3.0; do
  for ttl in TTL_ID_TOKEN=3s TTL_LOGIN_CONSENT_REQUEST=5s; do
    db=h$(echo $v | tr -d .)$port
    docker exec hydra-pg psql -U postgres -c "create database $db"
    dsn="postgres://postgres:hydra@$PG:5432/$db?sslmode=disable"
    docker run --rm -e DSN="$dsn" oryd/hydra:v$v migrate sql -e --yes
    docker run -d --rm --name hydra-$db -p 127.0.0.1:$port:4444 -p 127.0.0.1:$((port+1)):4445 -e DSN="$dsn" \
      -e SECRETS_SYSTEM=youReallyNeedToChangeThis -e URLS_SELF_ISSUER=http://127.0.0.1:$port \
      -e URLS_LOGIN=http://login.test/login -e URLS_CONSENT=http://login.test/consent -e URLS_LOGOUT=http://login.test/logout \
      -e URLS_POST_LOGOUT_REDIRECT=http://post.test/default -e $ttl oryd/hydra:v$v serve all --dev
    port=$((port+2))
  done
done
for admin in 56445 56447 56449 56451 56453 56455; do
  until curl -sf http://127.0.0.1:$admin/health/ready; do sleep 1; done
done
HYDRA_URLS='http://127.0.0.1:56444|http://127.0.0.1:56445,http://127.0.0.1:56448|http://127.0.0.1:56449,http://127.0.0.1:56452|http://127.0.0.1:56453' \
HYDRA_SHORT_URLS='http://127.0.0.1:56446|http://127.0.0.1:56447,http://127.0.0.1:56450|http://127.0.0.1:56451,http://127.0.0.1:56454|http://127.0.0.1:56455' \
  go test -race -tags integration ./internal/hydra/...
```

The golden files are rewritten with `-update`; review the diff:

- the emulated API's (`internal/hydra/testdata/emulated`):
  `go test ./internal/hydra -args -update`;
- the pages of the embedded theme, in each locale
  (`internal/front/testdata/pages`): `go test ./internal/front -args -update`.

The full stack (Hydra, login apps, Postgres, Redis) runs from the sibling
`hydra-dev` repository: `make up-go` there serves this dispatcher, built from
this checkout, on Hydra 2.1 (`make up-go-hydra22` on 2.2).

## Releases

A tag `v*` runs `.gitea/workflows/release.yaml`: the image is pushed by its digest to
`reg.cadoles.com/cadoles/hydra-dispatcher-go`, its CycloneDX SBOM (syft) attested, both
signed with cosign by the key pair of the dispatcher and verified; only then does the
digest get its tags, the version, `major.minor` and `latest`, so that a failed signature
leaves no tag on an unsigned image. The release of the forge gets the changelog and the
SBOM. Nothing goes to the public services of Sigstore
(`.gitea/cosign-signing-config.json` names none): a deployment checks the digest with
the public key alone, `cosign.pub` at the root of this repository:

```sh
cosign verify --key cosign.pub --insecure-ignore-tlog=true reg.cadoles.com/cadoles/hydra-dispatcher-go@sha256:<digest>
cosign verify-attestation --key cosign.pub --insecure-ignore-tlog=true --type cyclonedx reg.cadoles.com/cadoles/hydra-dispatcher-go@sha256:<digest>
```

Not ready yet: the owner creates the secrets of the repository, `REGISTRY_USERNAME` and
`REGISTRY_PASSWORD` (a robot account of the project cadoles), `COSIGN_PRIVATE_KEY` and
`COSIGN_PASSWORD` (the pair of `cosign generate-key-pair`), `RELEASE_TOKEN`, and commits
`cosign.pub`; without it, the workflow stops before building.

Dependencies follow `renovate.json`: minor and patch updates grouped each week and
merged once the CI passes, a pull request of its own for a major, `ory/hydra-client-go`
and BuildKit; actions and images pinned by digest. The scheduled run is the platform's.
`tini` (Dockerfile) is updated by hand, its checksums with it.

## End-to-end run

`examples/hydra-dev/e2e` is the browser and the OAuth2 client on hydra-dev's
three flows, through the real login apps, and checks the claims of the final
`id_token`: first login on each flow; second login, Hydra's skip honoured from
the `dispatcher_remember` cookie, then without it (the skip ignored, then
another account refused), with `prompt=consent` (the screen without a flow,
refused) and reloaded during the redirection; the logout, confirmed through the
`logout_url` of each app, refused, asked by a client with its `id_token_hint`,
and a chain stopped at an app, passed by a new demand, cut by the next login, not cut
by a preload of the login link, or left by the link of page E1003; what the apps answer
to a challenge that is not theirs; a preload and a change of language on the logout's
page; a subrequest of another site; `prompt=consent` accepted and refused; back to the
choice. Start `make up-go` in
`hydra-dev`, whose README sets the `*.hydra.test` names up, then:

```sh
go run ./examples/hydra-dev/e2e            # every default scenario
go run ./examples/hydra-dev/e2e -h         # flags and scenarios
go run ./examples/hydra-dev/e2e -v second-login
```

`-webhook http://10.0.6.1:<port>`, on a stack started with `HYDRA_DEV_WEBHOOK` at
the same URL, sends every scenario through a receiver that checks the signature;
the `webhook-*` scenarios need it, and run when named.

`-back-channel http://10.0.6.1:<port>` adds a check to the scenario of a chain
stopped: a client registered for the run hears of the session deleted on that
port of this host, which Hydra's container reaches. `-cookie-key` opens the note of
logout, hydra-dev's development key by default.

## Fixture tools

- `tools/recorder`: recording reverse proxy. `make capture` in `hydra-dev`
  builds it from `tools/recorder/Dockerfile` and puts it in front of the
  Symfony dispatcher and between the dispatcher and Hydra, `make capture-go`
  in front of this one; captured exchanges land in `testdata/capture/`
  (gitignored) and are sorted per scenario under `testdata/protocol/`, by
  `tools/scenarios` or by the e2e's `-into` (its `-symfony` drives the
  Symfony pages).
- `tools/flowfixtures`: records Hydra 2.2 login and consent challenges with the
  matching admin API responses, for `internal/hydra/flowcodec`. Run it against
  `make up-hydra22`:
  `go run ./tools/flowfixtures -client <client_id> -out internal/hydra/flowcodec/testdata/hydra-v2.2.0`.
  With `-errors`, Hydra's answers to unknown, handled, refused and expired
  requests, of any version (`internal/hydra/testdata/errors`); with `-secret` and
  `-post-logout` too, the logout's, for which it redeems an `id_token`. The command
  is at the top of `tools/flowfixtures/main.go`.
