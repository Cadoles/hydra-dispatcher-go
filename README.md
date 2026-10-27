# hydra-dispatcher-go

The single login app [Ory Hydra](https://github.com/ory/hydra) talks to. It
chains several real login apps into a flow (MFA, identity provider choice,
protocol choice) by replaying Hydra's login/consent protocol towards each of
them.

Go rewrite of the Symfony `hydra-dispatcher`. Work in progress: phase 0
(skeleton), the binary only serves `/health` for now.

## Commands

```
dispatcher serve         run the HTTP server on :8080
dispatcher healthcheck   probe /health of a local server (container HEALTHCHECK)
dispatcher version       print the version
```

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

The full stack (Hydra, login apps, Postgres, Redis) runs from the sibling
`hydra-dev` repository.

## Fixture tools

- `tools/recorder`: recording reverse proxy. `make capture` in `hydra-dev` puts
  it in front of the dispatcher and between the dispatcher and Hydra; captured
  exchanges are sorted per scenario under `testdata/protocol/`.
- `tools/flowfixtures`: records Hydra 2.2 login and consent challenges with the
  matching admin API responses, for `internal/hydra/flowcodec`. Run it against
  `make up-hydra22`:
  `go run ./tools/flowfixtures -client <client_id> -out internal/hydra/flowcodec/testdata/hydra-v2.2.0`
