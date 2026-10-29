# Recording proxy for the protocol fixtures, built by `make capture` in
# hydra-dev with the repository root as context. Keep both stages in step
# with ../../Dockerfile: same images, same digests.
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY . .
# Cache mounts: the build fetches only the modules it compiles, not the tools
# of go.mod.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/recorder ./tools/recorder

# hydra-dev runs it as the host user, so the captures stay theirs.
FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/recorder /recorder
ENTRYPOINT ["/recorder"]
