# hydra-dispatcher-go

The single login app [Ory Hydra](https://github.com/ory/hydra) talks to. It
chains several real login apps into a flow (MFA, identity provider choice,
protocol choice) by replaying Hydra's login/consent protocol towards each of
them.

Go rewrite of the Symfony `hydra-dispatcher-v2`. Work in progress, phase 1 (plan
and journal in `hydra-dev/conception`): the binary serves the pages (choice of
the flow, consent, errors, logout accepted at once until the confirmation of
P9), the emulated admin API the login apps call (v2 paths and v1 aliases),
`/health` and `/ready`; it keeps its configuration in Postgres and the flows in
progress in memory, or in Redis (or Dragonfly) when `state.redis_dsn` is set, a
call bounded to 1 s and two attempts unless its URL says otherwise (`dial_timeout`,
`read_timeout`, `write_timeout`, `max_retries`).

## Commands

```
hydra-dispatcher serve [-config dispatcher.yaml]    run the HTTP server
hydra-dispatcher migrate [-config ...]              apply the database migrations
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
refused) and reloaded during the redirection; a logout that clears the
cookie; `prompt=consent` accepted and refused; back to the choice. Start `make up-go` in `hydra-dev`, whose README sets the
`*.hydra.test` names up, then:

```sh
go run ./examples/hydra-dev/e2e            # every default scenario
go run ./examples/hydra-dev/e2e -h         # flags and scenarios
go run ./examples/hydra-dev/e2e -v second-login
```

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
  `go run ./tools/flowfixtures -client <client_id> -out internal/hydra/flowcodec/testdata/hydra-v2.2.0`
