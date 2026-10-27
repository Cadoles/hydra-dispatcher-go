# Recording proxy for the protocol fixtures, built by `make capture` in
# hydra-dev with the repository root as context. Keep the build stage in step
# with ../../Dockerfile.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/recorder ./tools/recorder

# hydra-dev runs it as the host user, so the captures stay theirs.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/recorder /recorder
ENTRYPOINT ["/recorder"]
