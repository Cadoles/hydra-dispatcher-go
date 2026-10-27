# hydra-dispatcher-go

The single login app [Ory Hydra](https://github.com/ory/hydra) talks to. It
chains several real login apps into a flow (MFA, identity provider choice,
protocol choice) by replaying Hydra's login/consent protocol towards each of
them.

Go rewrite of the Symfony `hydra-dispatcher`. Work in progress: phase 0
(skeleton), the binary only serves `/health` for now.

## Commands

```
dispatcher serve [-config dispatcher.yaml]   run the HTTP server
dispatcher healthcheck [-url ...]            probe /health of a local server (container HEALTHCHECK)
dispatcher version                           print the version
```

`serve` exposes `/health` (liveness) and `/ready` (Hydra reachable, within
2 s; 503 otherwise, details in the log). Logs are JSON lines on stdout,
`log_type` `app` or `access`, with the request's `trace_id`.

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
- Unknown keys are errors. Required: `server.base_url`, `hydra.admin_url`,
  `store.dsn`, `secrets.cookie_key`, `secrets.challenge_key`.

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
