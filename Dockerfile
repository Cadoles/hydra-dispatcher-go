# --- build stage ---
# Images pinned by digest, bumped by Renovate. This one sets GOTOOLCHAIN=local:
# keep its Go version that of the toolchain directive of go.mod.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
# tini, static, pinned by checksum (Q86): the init of the image, PID 1, which reaps
# what a local program of the webhooks leaves behind; the dispatcher does not.
ADD --checksum=sha256:c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee \
    https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-amd64 /tini/amd64
ADD --checksum=sha256:eae1d3aa50c48fb23b8cbdf4e369d0910dfc538566bfd09df89a774aa84a48b9 \
    https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-arm64 /tini/arm64
ARG TARGETARCH
RUN install -D -m 0755 /tini/${TARGETARCH} /out/tini
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
COPY --from=build /out/tini /tini
COPY --from=build /out/hydra-dispatcher /hydra-dispatcher
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s CMD ["/hydra-dispatcher", "healthcheck"]
# tini runs the dispatcher, forwards it the signals and reaps the orphans; an image
# built from this one without it takes docker run --init, or init: true in compose.
ENTRYPOINT ["/tini", "--", "/hydra-dispatcher"]
CMD ["serve"]
