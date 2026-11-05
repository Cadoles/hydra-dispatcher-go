# --- build stage ---
# Images pinned by digest, bumped by Renovate. This one sets GOTOOLCHAIN=local:
# keep its Go version that of the toolchain directive of go.mod.
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
# Cache mounts: the build fetches only the modules it compiles, not the tools
# of go.mod, and keeps them across go.mod changes.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/hydra-dispatcher ./cmd/hydra-dispatcher

# --- runtime stage ---
# No shell, no package manager: the binary probes itself for HEALTHCHECK, on
# the server.listen serve uses. Give the configuration file by
# DISPATCHER_CONFIG, which both read, rather than by "serve -config".
FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/hydra-dispatcher /hydra-dispatcher
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s CMD ["/hydra-dispatcher", "healthcheck"]
ENTRYPOINT ["/hydra-dispatcher"]
CMD ["serve"]
