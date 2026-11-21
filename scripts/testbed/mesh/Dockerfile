# The disposable Mesh of the rotation testbed: the API server of entire-vc/evc-mesh
# built from the source tree passed as the build context (a clean checkout of
# the commit the receipt names). Only the Go API is built: the web client is not
# part of what the stand proves. Nothing secret is baked in.
#
# Built with Mesh's own -tags e2eloopback (internal/service/extension_dial_e2eloopback.go):
# Mesh's SSRF guard refuses a loopback extension address in a release build, and
# the stand reaches Keep on loopback. That is Mesh's mechanism for a disposable
# stack; no Mesh source is changed. The receipt names the tag.
#
#   docker build -f scripts/testbed/mesh/Dockerfile <path to an evc-mesh checkout>
FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -tags e2eloopback -trimpath -ldflags="-s -w" -o /out/mesh-api ./cmd/api

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata curl
COPY --from=build /out/mesh-api /usr/local/bin/mesh-api
COPY migrations/ /app/migrations/
WORKDIR /app
EXPOSE 8005
CMD ["mesh-api"]
