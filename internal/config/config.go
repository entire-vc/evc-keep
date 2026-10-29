// Package config reads Keep Server's configuration from the process
// environment — the only configuration source, per CONTRIBUTING.md: every
// variable this reads carries the KEEP_ prefix.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Config is Keep Server's runtime configuration.
type Config struct {
	// DatabaseURL is KEEP_DATABASE_URL. It is never logged and never
	// appears in an error — see internal/store.Open's doc.
	DatabaseURL string
	PublicURL   string
	// MeshExtension is KEEP_MESH_EXTENSION exactly "1": serve the Mesh
	// extension routes. Off by default; Keep works the same without it.
	MeshExtension bool
	// MeshGate is the Mesh confirmation-card settings; the zero value is off.
	MeshGate MeshGate
	// MeshSelfRotate is the background rotation of the Mesh service token; the zero value is off.
	MeshSelfRotate MeshSelfRotate
	// HTTPAddr is KEEP_HTTP_ADDR, e.g. ":8080". Defaults to ":8080". Serves
	// only /healthz and /readyz — see cmd/keep-server's own doc for why
	// every credential-bearing route lives on RunnerAddr instead.
	HTTPAddr string
	// RunnerAddr is KEEP_RUNNER_ADDR, the TLS listener every runner
	// registration/enrollment/renewal/revocation route is served from.
	// Defaults to ":8443".
	RunnerAddr string
	// RootKeyFile is KEEP_ROOT_KEY_FILE: a path to a file holding exactly
	// 32 raw bytes or their standard base64 encoding, the root key
	// internal/builtin/sealer.NewLocalRootKey wraps every other key under.
	// Required for serving; migration commands do not load the root key.
	RootKeyFile string
	// RootKeyID is KEEP_ROOT_KEY_ID, the persistent key identifier stored
	// alongside wrapped KEKs. Defaults to "local-v1".
	RootKeyID string
	// ServerTLSCertFile and ServerTLSKeyFile are KEEP_SERVER_TLS_CERT_FILE
	// and KEEP_SERVER_TLS_KEY_FILE: the server-side certificate the TLS
	// listener presents to a connecting runner. This is Keep Server's own
	// server certificate — unrelated to any organization's CA — so an
	// empty pair is rejected unless DevEphemeralTLS is explicitly enabled.
	ServerTLSCertFile string
	ServerTLSKeyFile  string
	// DevEphemeralTLS allows a self-signed listener certificate only when
	// KEEP_DEV_EPHEMERAL_TLS is exactly "1".
	DevEphemeralTLS bool
	// CatalogRatePerMinute and CatalogBurst are KEEP_CATALOG_RATE_PER_MINUTE
	// and KEEP_CATALOG_BURST: the per-principal limit on the secret catalog
	// routes. Zero means the defaults (60 a minute, burst 20).
	CatalogRatePerMinute int
	CatalogBurst         int
	// TrustedProxies is KEEP_TRUSTED_PROXIES: comma-separated CIDR prefixes
	// of the reverse proxies whose X-Forwarded-For names the client of a Mesh
	// call. Empty: the peer is the client.
	TrustedProxies []netip.Prefix
}

// trustedProxies parses KEEP_TRUSTED_PROXIES; an empty variable is no proxy.
func trustedProxies() ([]netip.Prefix, error) {
	raw := strings.TrimSpace(os.Getenv("KEEP_TRUSTED_PROXIES"))
	if raw == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, f := range strings.Split(raw, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(f))
		if err != nil {
			return nil, errors.New("KEEP_TRUSTED_PROXIES must be comma-separated CIDR prefixes, e.g. 127.0.0.1/32")
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func positiveInt(name string) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return n, nil
}

// FromEnv reads Config from the process environment.
func FromEnv() (Config, error) {
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		return Config{}, errors.New("KEEP_DATABASE_URL is required")
	}
	addr := os.Getenv("KEEP_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	runnerAddr := os.Getenv("KEEP_RUNNER_ADDR")
	if runnerAddr == "" {
		runnerAddr = ":8443"
	}
	rootKeyID := os.Getenv("KEEP_ROOT_KEY_ID")
	if rootKeyID == "" {
		rootKeyID = "local-v1"
	}
	meshExt := os.Getenv("KEEP_MESH_EXTENSION") == "1"
	gate, err := meshGateFromEnv(meshExt)
	if err != nil {
		return Config{}, err
	}
	selfRotate, err := meshSelfRotateFromEnv(meshExt)
	if err != nil {
		return Config{}, err
	}
	rate, err := positiveInt("KEEP_CATALOG_RATE_PER_MINUTE")
	if err != nil {
		return Config{}, err
	}
	burst, err := positiveInt("KEEP_CATALOG_BURST")
	if err != nil {
		return Config{}, err
	}
	proxies, err := trustedProxies()
	if err != nil {
		return Config{}, err
	}
	return Config{
		TrustedProxies:       proxies,
		CatalogRatePerMinute: rate,
		CatalogBurst:         burst,
		DatabaseURL:          dsn,
		PublicURL:            os.Getenv("KEEP_PUBLIC_URL"),
		MeshExtension:        meshExt,
		MeshGate:             gate,
		MeshSelfRotate:       selfRotate,
		HTTPAddr:             addr,
		RunnerAddr:           runnerAddr,
		RootKeyFile:          os.Getenv("KEEP_ROOT_KEY_FILE"),
		RootKeyID:            rootKeyID,
		ServerTLSCertFile:    os.Getenv("KEEP_SERVER_TLS_CERT_FILE"),
		ServerTLSKeyFile:     os.Getenv("KEEP_SERVER_TLS_KEY_FILE"),
		DevEphemeralTLS:      os.Getenv("KEEP_DEV_EPHEMERAL_TLS") == "1",
	}, nil
}
