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
hydra-dispatcher version                            print the version
```

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

`serve` exposes `/health` (liveness) and `/ready` (Hydra, the database and
the state store reachable, within 2 s, Redis by a `PING`; 503 otherwise,
details in the log). It reads the
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
page; `prompt=consent` accepted and refused; back to the choice. Start `make up-go` in
`hydra-dev`, whose README sets the `*.hydra.test` names up, then:

```sh
go run ./examples/hydra-dev/e2e            # every default scenario
go run ./examples/hydra-dev/e2e -h         # flags and scenarios
go run ./examples/hydra-dev/e2e -v second-login
```

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
