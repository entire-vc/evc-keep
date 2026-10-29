# amd64 only: matches the current Keep runner/cache architecture.
FROM golang:1.25.14-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437
# Debian package resolution occurs only at image build time. The published image
# must be pinned by digest; record inventory and rebuild for security updates.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium curl ca-certificates xz-utils python3 \
 && mkdir -p /usr/local/share/intake-image \
 && dpkg-query -W > /usr/local/share/intake-image/packages.txt \
 && rm -rf /var/lib/apt/lists/*
RUN test "$(dpkg --print-architecture)" = amd64 \
 && curl --fail --silent --show-error --location \
    https://nodejs.org/dist/v22.22.3/node-v22.22.3-linux-x64.tar.xz -o /tmp/node.tar.xz \
 && echo '2e5d13569282d016861fae7c8f935e741693c269101a5bebcf761a5376d1f99f  /tmp/node.tar.xz' | sha256sum --check --strict \
 && tar -xJf /tmp/node.tar.xz --strip-components=1 --directory=/usr/local \
 && rm /tmp/node.tar.xz \
 && test "$(node --version)" = v22.22.3 \
 && go version && chromium --version && python3 --version && gcc --version \
 && chromium --headless --no-sandbox --disable-dev-shm-usage --dump-dom 'data:text/html,<title>intake-image-smoke</title>' 2>/dev/null | grep -q intake-image-smoke
# No source, Go module/build cache, credentials or application artifacts are baked in.
