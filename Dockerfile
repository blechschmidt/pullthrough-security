# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Multi-stage build for the pull-through security proxy.
#
# Stage 1 (build) compiles a static, stripped binary with the version stamped
# in via -ldflags. Build caches for the module download and the Go build cache
# are mounted so incremental rebuilds are fast and reproducible.
#
# Stage 2 (runtime) is a minimal Alpine image carrying only the binary, the
# CA bundle, and the git/openssh client binaries the Git mirror subsystem shells
# out to. It runs as a non-root user and declares a HEALTHCHECK against /healthz.
# ---------------------------------------------------------------------------

ARG GO_VERSION=1.24.1
ARG ALPINE_VERSION=3.20

# --- build stage -----------------------------------------------------------
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

# git is needed for `go build` of VCS-stamped binaries and for module fetches
# that resolve via VCS. Keep this layer cheap; modules are cached below.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Download dependencies first so the layer is cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy the rest of the source and build.
COPY . .

# VERSION is injected by CI (git describe). Defaults to "dev" for local builds.
ARG VERSION=dev
# Target platform args are provided automatically by BuildKit for cross-builds.
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/pullthrough \
        ./cmd/pullthrough

# --- runtime stage ---------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS runtime

# ca-certificates: outbound TLS to upstreams.
# git + openssh-client: the Git mirror/SSH proxy subsystem execs these.
# tini: proper PID 1 signal handling and zombie reaping.
RUN apk add --no-cache ca-certificates git openssh-client tini \
    && addgroup -S -g 65532 pullthrough \
    && adduser -S -u 65532 -G pullthrough -h /home/pullthrough pullthrough \
    && mkdir -p /var/lib/pullthrough \
    && chown -R pullthrough:pullthrough /var/lib/pullthrough

COPY --from=build /out/pullthrough /usr/local/bin/pullthrough
COPY configs/config.example.yaml /etc/pullthrough/config.example.yaml

# State (cache, audit log, provenance/scan stores) lives here; mount a volume.
VOLUME ["/var/lib/pullthrough"]

USER 65532:65532
EXPOSE 8080
# SSH Git gateway (only listens when server.sshAddr is set).
EXPOSE 2222

# Container-level liveness; the orchestrator probes are authoritative in k8s.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/pullthrough"]
CMD ["-config", "/etc/pullthrough/config.yaml"]
