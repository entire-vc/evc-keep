# keep-server image. Builds without a privileged daemon (kaniko-compatible:
# no RUN --mount, no BuildKit-only syntax) and runs as a non-root user.
#
#   docker build -t keep-server .
#   docker build --build-arg SERVER_VARIANT=mesh -t keep-server:mesh .
#
# SERVER_VARIANT picks the binary: "core" (the default) is cmd/keep-server
# and carries no Mesh code; "mesh" is plugins/mesh/cmd/keep-server, the same
# server with the Mesh plugin (confirmation cards, the service token).
# Nothing secret is baked in: the image carries no configuration values.
# Every KEEP_* setting arrives at run time; see docs/deploy.md.

FROM golang:1.25.14-alpine3.24@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
ARG SERVER_VARIANT=core
WORKDIR /src
COPY go.mod go.sum ./
COPY plugins/mesh/go.mod plugins/mesh/go.sum ./plugins/mesh/
RUN go mod download && cd plugins/mesh && go mod download
COPY . .
# The build context carries no .git (and -buildvcs=false below), so the commit
# the image is built from must be passed in, or GET /version reports "unknown":
#   docker build --build-arg BUILD_COMMIT=$(git rev-parse HEAD) \
#     --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) -t keep-server .
# Declared after COPY so that a new value invalidates only the compile layer.
ARG BUILD_COMMIT=unknown
ARG BUILD_TIME=unknown
RUN case "$SERVER_VARIANT" in \
      core) dir=. ;; \
      mesh) dir=plugins/mesh ;; \
      *) echo "SERVER_VARIANT must be core or mesh" >&2; exit 1 ;; \
    esac && cd "$dir" && CGO_ENABLED=0 GOFLAGS=-buildvcs=false \
    go build -trimpath \
    -ldflags="-s -w -X github.com/entire-vc/evc-keep/internal/version.Commit=${BUILD_COMMIT} -X github.com/entire-vc/evc-keep/internal/version.BuildDate=${BUILD_TIME}" \
    -o /out/keep-server ./cmd/keep-server

FROM alpine:3.24
RUN addgroup -S -g 10001 keep && adduser -S -u 10001 -G keep -H -s /sbin/nologin keep
COPY --from=build /out/keep-server /usr/local/bin/keep-server
USER 10001:10001
# 8080: /healthz, /readyz and /version only. 8443: the TLS listener for runners.
EXPOSE 8080 8443
# /healthz never touches the database; /readyz is the database check and is
# for the orchestrator's readiness probe, not for restarting the container.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/keep-server"]
