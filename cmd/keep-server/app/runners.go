// runners.go wires cmd/keep-server's dependencies for the runner
// registration/renewal/revocation routes — the one place in
// the binary allowed to import internal/builtin/orgpki alongside
// internal/api and internal/mtls (scripts/check-import-boundaries.sh's
// zone-internals rule).
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/google/uuid"
)

// orgpkiCertIssuer adapts *orgpki.Repo to api.CertIssuer.
type orgpkiCertIssuer struct{ repo *orgpki.Repo }

func (a orgpkiCertIssuer) IssueRunnerCert(ctx context.Context, orgID, runnerID uuid.UUID, host string, csrDER []byte) (api.RunnerCertIssued, error) {
	cert, err := a.repo.IssueRunnerCert(ctx, orgID, runnerID, host, csrDER)
	if err != nil {
		if errors.Is(err, orgpki.ErrInvalidCSR) {
			return api.RunnerCertIssued{}, api.ErrCertIssuerInvalidCSR
		}
		return api.RunnerCertIssued{}, err
	}
	return api.RunnerCertIssued{
		CertDER:    cert.CertDER,
		CACertDER:  cert.CACertDER,
		SignKeyID:  cert.SignKeyID,
		SignPubKey: []byte(cert.SignPubKey),
		NotAfter:   cert.NotAfter,
	}, nil
}

// orgpkiCAResolver uses only public CA material authenticated before the
// request. A certificate's untrusted organization claim never opens sealed
// private keys or causes a new CA to be minted.
type orgpkiCAResolver struct{ repo *orgpki.Repo }

func (a orgpkiCAResolver) CACert(_ context.Context, orgID uuid.UUID) ([]byte, bool, error) {
	der, ok := a.repo.CachedCACert(orgID)
	return der, ok, nil
}

// serverTLSCert resolves the certificate the runner TLS listener presents.
// An empty pair is rejected unless the operator explicitly enables the
// development-only ephemeral certificate.
func serverTLSCert(cfg config.Config, logger *slog.Logger) (tls.Certificate, error) {
	if cfg.ServerTLSCertFile != "" && cfg.ServerTLSKeyFile != "" {
		return tls.LoadX509KeyPair(cfg.ServerTLSCertFile, cfg.ServerTLSKeyFile)
	}
	if cfg.ServerTLSCertFile != "" || cfg.ServerTLSKeyFile != "" {
		return tls.Certificate{}, errors.New("both KEEP_SERVER_TLS_CERT_FILE and KEEP_SERVER_TLS_KEY_FILE are required")
	}
	if !cfg.DevEphemeralTLS {
		return tls.Certificate{}, errors.New("KEEP_SERVER_TLS_CERT_FILE and KEEP_SERVER_TLS_KEY_FILE are required; set KEEP_DEV_EPHEMERAL_TLS=1 only for development")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "keep-server ephemeral"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	logger.Warn("keep-server: using an ephemeral, non-persistent TLS server certificate — set KEEP_SERVER_TLS_CERT_FILE/KEEP_SERVER_TLS_KEY_FILE for a real one")
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
