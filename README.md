# hydra-dispatcher-go

The single login app [Ory Hydra](https://github.com/ory/hydra) talks to. It
chains several real login apps into a flow (MFA, identity provider choice,
protocol choice) by replaying Hydra's login/consent protocol towards each of
them.

Go rewrite of the Symfony `hydra-dispatcher`. Work in progress: phase 1, the
binary serves `/health` and `/ready`, and keeps its configuration in Postgres.

## Commands

```
dispatcher serve [-config dispatcher.yaml]          run the HTTP server
dispatcher migrate [-config ...]                    apply the database migrations
dispatcher bootstrap [-config ...] [-force] [-dry-run] [-yes]
                                                    write the seed of the configuration file to the database
dispatcher healthcheck [-url ...]                   probe /health of a local server (container HEALTHCHECK)
dispatcher version                                  print the version
```

`-config` defaults to `$DISPATCHER_CONFIG`, which `healthcheck` reads too for
the `server.listen` to probe: in a container, give the file by the variable.

`bootstrap` creates what the database lacks from the `dispatcher:` block (the
seed); `-force` rewrites too what the database holds of it, and resets the
settings the seed sets to `~`. Neither deletes. `-dry-run` prints the changes
and writes nothing; in a terminal, `-force` prints them and asks, unless
`-yes`. `serve` migrates at startup with `serve.migrate: true`, and
bootstraps with `serve.bootstrap: missing` or `force`, logging the changes.

`serve` exposes `/health` (liveness) and `/ready` (Hydra and the database
reachable, within 2 s; 503 otherwise, details in the log). It reads the
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
  clients connect directly), `hydra.admin_url`, `store.dsn`,
  `secrets.cookie_key`, `secrets.challenge_key`.

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

The emulated API's golden files (`internal/hydra/testdata/emulated`) are
rewritten with `go test ./internal/hydra -args -update`; review the diff.

The full stack (Hydra, login apps, Postgres, Redis) runs from the sibling
`hydra-dev` repository.

## Fixture tools

- `tools/recorder`: recording reverse proxy. `make capture` in `hydra-dev`
  builds it from `tools/recorder/Dockerfile` and puts it in front of the
  dispatcher and between the dispatcher and Hydra; captured exchanges land in
  `testdata/capture/` (gitignored) and are sorted per scenario under
  `testdata/protocol/`.
- `tools/flowfixtures`: records Hydra 2.2 login and consent challenges with the
  matching admin API responses, for `internal/hydra/flowcodec`. Run it against
  `make up-hydra22`:
  `go run ./tools/flowfixtures -client <client_id> -out internal/hydra/flowcodec/testdata/hydra-v2.2.0`
