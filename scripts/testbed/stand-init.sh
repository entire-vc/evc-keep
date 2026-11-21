#!/bin/sh
# Runs in the operator container, once per stand. Makes the synthetic root key,
# the server's certificate (which is also the hosts' trust anchor) and the
# settings file keep-server reads at start. Nothing here is a real credential:
# the stand's data is destroyed with its volumes.
set -eu
umask 077
install -d -m 0755 /stand /pki /operator
install -d -m 1777 /exchange
if [ ! -e /stand/server.env ]; then
  head -c 32 /dev/urandom | base64 > /stand/root-key
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -subj "/CN=keep-server" -addext "subjectAltName=DNS:keep-server,DNS:localhost,IP:127.0.0.1" \
    -keyout /stand/server.key -out /stand/server.pem 2>/dev/null
  cp /stand/server.pem /pki/server-ca.pem
  chmod 0644 /pki/server-ca.pem
  cat > /stand/server.env <<'ENV'
export KEEP_DATABASE_URL='postgres://keep@postgres:5432/keep?sslmode=disable'
export KEEP_ROOT_KEY_FILE=/stand/root-key
export KEEP_HTTP_ADDR=:8080
export KEEP_RUNNER_ADDR=:8443
export KEEP_PUBLIC_URL=http://127.0.0.1:8080
export KEEP_SERVER_TLS_CERT_FILE=/stand/server.pem
export KEEP_SERVER_TLS_KEY_FILE=/stand/server.key
ENV
  # The server runs as uid 10001 and reads these through a read-only mount.
  chown -R 10001:10001 /stand
fi
# The Mesh stand (stand-init.sh mesh): the settings of the disposable Mesh, made
# here once, and the rotation settings keep-server reads at start. The two
# files rotation.sh fills later (the service token and the bindings) are read
# by keep-server on every call, so no restart is needed when they change.
if [ "${1:-}" = mesh ] && [ ! -e /meshconf/mesh.env ]; then
  install -d -m 0755 /meshconf
  install -d -m 0755 /exchange/mesh
  printf 'placeholder-until-mesh-setup' > /exchange/mesh/rotate-token; printf '{}' > /exchange/mesh/bindings.json
  chown 10001:10001 /exchange/mesh/rotate-token /exchange/mesh/bindings.json
  chmod 0600 /exchange/mesh/rotate-token /exchange/mesh/bindings.json
  cat >> /stand/server.env <<'ENV'
export KEEP_MESH_EXTENSION=1
export KEEP_MESH_ROTATE_URL=http://localhost:8005
export KEEP_MESH_ROTATE_TOKEN_FILE=/exchange/mesh/rotate-token
export KEEP_MESH_ROTATE_BINDINGS=/exchange/mesh/bindings.json
ENV
  {
    echo "export SERVER_PORT=8005 DB_HOST=mesh-postgres DB_PORT=5432 DB_USER=mesh DB_NAME=mesh DB_SSL_MODE=disable"
    echo "export REDIS_HOST=mesh-redis REDIS_PORT=6379"
    echo "export S3_ENDPOINT=http://mesh-s3.invalid:9000 S3_ACCESS_KEY_ID=stand S3_SECRET_ACCESS_KEY=stand S3_BUCKET=stand S3_REGION=us-east-1 S3_USE_SSL=false"
    echo "export SSL_CERT_FILE=/pki/server-ca.pem"
    echo "export MESH_ALLOW_REGISTRATION=true MESH_RATE_LIMIT_ENABLED=false"
    echo "export JWT_SECRET='$(head -c 32 /dev/urandom | base64 | tr -d '\n')'"
    echo "export MESH_INTEGRATION_ENCRYPTION_KEY='$(head -c 32 /dev/urandom | base64 | tr -d '\n')'"
  } > /meshconf/mesh.env
  chmod 0600 /meshconf/mesh.env
fi
echo ok
