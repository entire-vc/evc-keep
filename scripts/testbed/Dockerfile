# Images of the rotation testbed (docs/rotation-testbed.md). One build stage
# compiles every binary the stand runs; the images below only copy from it.
#
#   docker build -f scripts/testbed/Dockerfile --target server .
#
# Nothing secret is baked in: keys, certificates and tokens are made when the
# stand starts and live in volumes.

FROM golang:1.25.14-alpine3.24@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY plugins/mesh/go.mod plugins/mesh/go.sum ./plugins/mesh/
RUN go mod download && cd plugins/mesh && go mod download
COPY . .
ARG BUILD_COMMIT=unknown
ARG BUILD_TIME=unknown
# core (the default) is cmd/keep-server; mesh is plugins/mesh/cmd/keep-server,
# the build the Mesh stand rotates agent keys with.
ARG SERVER_VARIANT=core
RUN set -eu; mkdir /out; \
    flags="-s -w -X github.com/entire-vc/evc-keep/internal/version.Commit=${BUILD_COMMIT} -X github.com/entire-vc/evc-keep/internal/version.BuildDate=${BUILD_TIME}"; \
    for p in cmd/keep-runner cmd/keep scripts/testbed/consumer scripts/testbed/leakscan; do \
      CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build -trimpath -ldflags="$flags" -o /out/$(basename $p) ./$p; \
    done; \
    case "$SERVER_VARIANT" in \
      core) dir=.; ;; \
      mesh) dir=plugins/mesh; ;; \
      *) echo "SERVER_VARIANT must be core or mesh" >&2; exit 1 ;; \
    esac; \
    (cd "$dir" && CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build -trimpath -ldflags="$flags" -o /out/keep-server ./cmd/keep-server); \
    CGO_ENABLED=0 GOFLAGS=-buildvcs=false go test -c -trimpath -ldflags="$flags" -o /out/humaninput ./scripts/testbed/humaninput; \
    CGO_ENABLED=0 GOFLAGS=-buildvcs=false go test -c -trimpath -ldflags="$flags" -o /out/meshcatalog ./scripts/testbed/meshcatalog; \
    cd /out && sha256sum * > /out/SHA256SUMS

# keep-server and its PostgreSQL schema tool, as an unprivileged user.
FROM debian:bookworm-slim AS server
ARG BUILD_COMMIT=unknown
LABEL org.opencontainers.image.revision=$BUILD_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin keep
COPY --from=build /out/keep-server /usr/local/bin/keep-server
COPY --from=build /out/SHA256SUMS /usr/local/share/keep-SHA256SUMS
COPY --chmod=0755 scripts/testbed/server-entry.sh /usr/local/bin/server-entry.sh
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/server-entry.sh"]

# The agent's and the operator's workstation: the keep CLI, plus the stand's
# own helpers (the human at the input page, the leak scanner).
FROM debian:bookworm-slim AS tools
ARG BUILD_COMMIT=unknown
LABEL org.opencontainers.image.revision=$BUILD_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq openssl postgresql-client && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/keep /out/humaninput /out/leakscan /usr/local/bin/
COPY --from=build /out/SHA256SUMS /usr/local/share/keep-SHA256SUMS
COPY --chmod=0644 scripts/testbed/host/policy-host-a.json scripts/testbed/host/policy-host-b.json /etc/keep-testbed/
COPY --chmod=0755 scripts/testbed/stand-init.sh scripts/testbed/mesh-setup.sh /usr/local/bin/
CMD ["sleep", "infinity"]

# A host: Debian with systemd as PID 1, its own keep-runner and five-minus-some
# consumers (see host/). Units are enabled at build time; the runner is
# enrolled and started by the stand's `up`.
FROM debian:bookworm AS host
ARG BUILD_COMMIT=unknown
LABEL org.opencontainers.image.revision=$BUILD_COMMIT
# Installing systemd and dbus writes a machine id into the image, which every
# container of it would share. Left empty, systemd gives each host its own at boot.
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates curl jq procps iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && find /etc/systemd/system /lib/systemd/system -path '*.wants/*' \( -name '*getty*' -o -name '*systemd-timesyncd*' -o -name '*apt-daily*' -o -name '*systemd-update-utmp*' \) -delete \
 && useradd --system --uid 2001 --no-create-home --shell /usr/sbin/nologin svc \
 && useradd --system --uid 3001 --no-create-home --shell /usr/sbin/nologin agent \
 && : >/etc/machine-id && ln -sf /etc/machine-id /var/lib/dbus/machine-id
COPY --from=build /out/keep-runner /out/consumer /usr/local/bin/
COPY --from=build /out/SHA256SUMS /usr/local/share/keep-SHA256SUMS
COPY --chmod=0755 scripts/testbed/host/ /opt/testbed-host/
RUN /opt/testbed-host/install.sh
STOPSIGNAL SIGRTMIN+3
# Docker mounts / and /run with private propagation. systemd sets up a unit's
# credentials (LoadCredentialEncrypted=) in a helper's own mount namespace and
# relies on that mount reaching the unit through shared propagation; with
# private mounts the unit gets an empty credentials directory. So / is made
# shared before systemd starts, as on a booted machine.
CMD ["/bin/sh", "-c", "mount --make-rshared / && exec /sbin/init"]

# The Mesh stand's side service: the signed catalog Mesh installs keep-rotator
# from, and the extension's own install endpoint. Runs in the namespace of the
# disposable Mesh.
FROM debian:bookworm-slim AS meshaux
ARG BUILD_COMMIT=unknown
LABEL org.opencontainers.image.revision=$BUILD_COMMIT
COPY --from=build /out/meshcatalog /usr/local/bin/meshcatalog
RUN mkdir -p -m 0755 /etc/keep-testbed
COPY --chmod=0644 mesh-extension.keep-rotator.json /etc/keep-testbed/keep-rotator.json
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/meshcatalog", "-test.run", "TestServe", "-test.v"]
