// Package orgpki is one organization's certificate authority: an Ed25519
// CA keypair and a separate Ed25519 job-signing keypair (the key
// pkg/runnerproto.Signer/VerifyJob use), both generated on first use and
// kept sealed at rest through internal/builtin/sealer. Only the two public
// halves (the CA certificate, the job-signing public key) ever leave this
// package; the private halves are unwrapped only for the instant
// [Repo.IssueRunnerCert] needs them to sign a CSR, and wiped immediately
// after.
//
// ADR-001 §3.2 ("Registration"), threat model §2.3 (S, E). See
// scripts/check-import-boundaries.sh's "sealer" rule for why this package
// must live under internal/builtin: it is the only place internal/builtin
// (and so internal/builtin/sealer) may be imported from besides
// cmd/keep-server and cmd/keep-runner.
package orgpki

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgForeignKeyViolation is the SQLSTATE Postgres raises for a foreign key
// violation — org_id not referencing a real row in organizations.
const pgForeignKeyViolation = "23503"

// caValidity is deliberately long: an organization's CA is meant to outlive
// many runner-certificate renewal cycles (each runner cert is
// [RunnerCertValidity]). Rotating it is a separate, later operation, not
// covered by this card.
const caValidity = 10 * 365 * 24 * time.Hour

// RunnerCertValidity is the lifetime of a signed runner certificate — the
// lead's decision quoted on the card: 30 days, renewed over an existing
// mTLS connection.
const RunnerCertValidity = 30 * 24 * time.Hour

// clockSkew backdates NotBefore the same way pkg/runnerproto.ClockSkew
// tolerates a runner's clock lagging the server's.
const clockSkew = 5 * time.Minute

// ErrInvalidCSR is returned for a CSR that doesn't parse, doesn't verify
// against its own embedded public key, or doesn't carry an Ed25519 key —
// Keep only issues Ed25519 runner certificates, matching every other
// signing key in this codebase.
var ErrInvalidCSR = errors.New("orgpki: invalid certificate signing request")

// ErrOrgNotFound is returned when orgID names no row in organizations —
// [Repo.Ensure] refuses to mint a CA for an organization that does not
// exist.
var ErrOrgNotFound = errors.New("orgpki: organization not found")

// ErrCAKeyMismatch is returned by [Repo.IssueRunnerCert] when the sealed CA
// private key it just unwrapped does not match the ca_cert_der stored
// alongside it — see the check's own doc comment for why this can happen.
var ErrCAKeyMismatch = errors.New("orgpki: sealed CA key does not match stored CA certificate")

// Bundle is the public half of an organization's PKI material: what a
// caller may hand to a runner or use to verify one. It never carries a
// private key.
type Bundle struct {
	CACertDER []byte
	SignKeyID string
	// SignPubKey is the org's job-signing public key — the key a runner
	// pins into a pkg/runnerproto.TrustedKeys at enrollment.
	SignPubKey ed25519.PublicKey
}

// RunnerCert is what [Repo.IssueRunnerCert] returns: a freshly signed
// client certificate for one runner, plus the public PKI material the
// runner must pin.
type RunnerCert struct {
	CertDER []byte
	Bundle
	NotAfter time.Time
}

// Repo is org PKI storage: the org_ca table, and the sealer that seals and
// opens the two private keys it holds.
type Repo struct {
	db              *pgxpool.Pool
	sealer          *sealer.Sealer
	cacheMu         sync.RWMutex
	verificationCAs map[uuid.UUID][]byte
}

// NewRepo wraps an already-open pool and sealer as a Repo.
func NewRepo(db *pgxpool.Pool, s *sealer.Sealer) *Repo {
	return &Repo{db: db, sealer: s}
}

// noopAuditor is the test fixture's auditor for Seal/Open operations.
type noopAuditor struct{}

func (noopAuditor) Record(sealer.Event) {}

// NewRepoFromKey is a standalone constructor for consumers without a
// builtin provider. The server uses NewRepoFromLocal to share its Sealer.
// The constructor consumes and wipes key on every path.
func NewRepoFromKey(db *pgxpool.Pool, keyID string, key []byte) (*Repo, error) {
	// The events go nowhere: this constructor must never reach an
	// administrative operation (key-level change, purge); the server wires a
	// journaling sink through builtin.OpenLocalFile instead.
	local, err := builtin.NewLocal(db, keyID, key, nil, func(builtin.KeyEvent) {})
	if err != nil {
		return nil, err
	}
	return NewRepoFromLocal(db, local), nil
}

// NewRepoFromLocal reuses the process root and Sealer without importing
// key-handling types into the command wiring layer.
func NewRepoFromLocal(db *pgxpool.Pool, local *builtin.Local) *Repo {
	return NewRepo(db, local.Sealer())
}

// Ensure returns orgID's PKI bundle, generating and sealing a fresh CA and
// job-signing key on first call for that organization. Concurrent first
// calls for the same org race on an INSERT ... ON CONFLICT DO NOTHING and
// then both re-read the row, so exactly one generated keypair ever survives
// per organization however many callers race to create it.
func (r *Repo) Ensure(ctx context.Context, orgID uuid.UUID) (Bundle, error) {
	if b, ok, err := r.load(ctx, orgID); err != nil {
		return Bundle{}, err
	} else if ok {
		r.cacheCA(orgID, b.CACertDER)
		return b, nil
	}

	rec, err := generate(ctx, orgID, r.sealer)
	if err != nil {
		return Bundle{}, fmt.Errorf("orgpki: generate org CA: %w", err)
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO org_ca (org_id, ca_cert_der, ca_kek_id, ca_wrapped_dek, ca_ciphertext,
			sign_key_id, sign_pub_key, sign_kek_id, sign_wrapped_dek, sign_ciphertext)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (org_id) DO NOTHING`,
		orgID, rec.caCertDER, rec.caEnv.KEKID, rec.caEnv.WrappedDEK, rec.caEnv.Ciphertext,
		rec.signKeyID, rec.signPubKey, rec.signEnv.KEKID, rec.signEnv.WrappedDEK, rec.signEnv.Ciphertext)
	if err != nil {
		if isForeignKeyViolation(err) {
			return Bundle{}, ErrOrgNotFound
		}
		return Bundle{}, fmt.Errorf("orgpki: store org CA: %w", err)
	}

	b, ok, err := r.load(ctx, orgID)
	if err != nil {
		return Bundle{}, err
	}
	if !ok {
		return Bundle{}, fmt.Errorf("orgpki: org CA missing immediately after insert")
	}
	r.cacheCA(orgID, b.CACertDER)
	return b, nil
}

// IssueRunnerCert signs csrDER under orgID's CA for (orgID, runnerID, host)
// — the server decides every field of the certificate's Subject and SAN
// itself; nothing from the CSR's own Subject is ever used (ADR-001 §3.2:
// tenant, runner and host are taken only from the certificate). It also ensures
// the organization's CA exists, so a first enrollment in a fresh
// organization does not need a separate provisioning step.
func (r *Repo) IssueRunnerCert(ctx context.Context, orgID, runnerID uuid.UUID, host string, csrDER []byte) (RunnerCert, error) {
	bundle, err := r.Ensure(ctx, orgID)
	if err != nil {
		return RunnerCert{}, err
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return RunnerCert{}, ErrInvalidCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return RunnerCert{}, ErrInvalidCSR
	}
	runnerPub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return RunnerCert{}, ErrInvalidCSR
	}

	caCert, err := x509.ParseCertificate(bundle.CACertDER)
	if err != nil {
		return RunnerCert{}, fmt.Errorf("orgpki: parse stored CA certificate: %w", err)
	}

	caPriv, err := r.unsealCAKey(ctx, orgID)
	if err != nil {
		return RunnerCert{}, err
	}
	defer wipe(caPriv)
	// The stored ca_cert_der and the sealed CA private key are written
	// together in generate(), but nothing before this point re-checks that
	// they still pair up: a row edited independently of the sealed
	// ciphertext (a swapped ca_cert_der, or a wrapped_dek pointing at a
	// different key). x509.CreateCertificate below already refuses to sign
	// with a key that doesn't match tmpl's parent, so this check is
	// defense-in-depth against exactly that stdlib behavior ever changing —
	// it turns "sign fails with an opaque x509 error" into a named,
	// diagnosable error pointing at the org whose CA row is inconsistent.
	if !ed25519.PrivateKey(caPriv).Public().(ed25519.PublicKey).Equal(caCert.PublicKey) {
		return RunnerCert{}, fmt.Errorf("%w for org %s", ErrCAKeyMismatch, orgID)
	}

	serial, err := randSerial()
	if err != nil {
		return RunnerCert{}, err
	}
	now := time.Now()
	notAfter := now.Add(RunnerCertValidity)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{orgID.String()},
			CommonName:   runnerID.String(),
		},
		DNSNames:              []string{host},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, runnerPub, ed25519.PrivateKey(caPriv))
	if err != nil {
		return RunnerCert{}, fmt.Errorf("orgpki: sign runner certificate: %w", err)
	}

	return RunnerCert{CertDER: leafDER, Bundle: bundle, NotAfter: notAfter}, nil
}

type record struct {
	caCertDER  []byte
	caEnv      sealer.Envelope
	signKeyID  string
	signPubKey []byte
	signEnv    sealer.Envelope
}

// generate creates a brand-new self-signed CA and a separate job-signing
// keypair, and seals both private keys. It touches no storage — the caller
// persists the returned record.
func generate(ctx context.Context, orgID uuid.UUID, s *sealer.Sealer) (record, error) {
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return record{}, err
	}
	defer wipe(caPriv)

	serial, err := randSerial()
	if err != nil {
		return record{}, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{orgID.String()},
			CommonName:   "Keep org CA " + orgID.String(),
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		return record{}, fmt.Errorf("create org CA certificate: %w", err)
	}

	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return record{}, err
	}
	defer wipe(signPriv)

	var idb [8]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return record{}, err
	}
	signKeyID := "orgsign_" + hex.EncodeToString(idb[:])

	caVal := secret.New(caPriv)
	defer caVal.Wipe() // secret.New copies caPriv; Seal doesn't consume/wipe its Value argument
	caEnv, err := s.Seal(ctx, caRef(orgID, caCertDER), caVal)
	if err != nil {
		return record{}, fmt.Errorf("seal CA private key: %w", err)
	}
	signVal := secret.New(signPriv)
	defer signVal.Wipe()
	signEnv, err := s.Seal(ctx, signRef(orgID, signKeyID, signPub), signVal)
	if err != nil {
		return record{}, fmt.Errorf("seal job-signing private key: %w", err)
	}

	return record{
		caCertDER:  caCertDER,
		caEnv:      caEnv,
		signKeyID:  signKeyID,
		signPubKey: append([]byte(nil), signPub...),
		signEnv:    signEnv,
	}, nil
}

// Lookup returns orgID's PKI bundle if one already exists, without
// [Ensure]'s side effect of generating a fresh CA for an organization that
// doesn't have one yet. Lookup authenticates private and public material, so
// an mTLS request path must use CachedCACert instead.
func (r *Repo) Lookup(ctx context.Context, orgID uuid.UUID) (Bundle, bool, error) {
	return r.load(ctx, orgID)
}

// CachedCACert returns only a CA authenticated during startup or Ensure.
// It performs no database or sealer operation on a request path carrying an
// unauthenticated certificate's claimed organization ID.
func (r *Repo) CachedCACert(orgID uuid.UUID) ([]byte, bool) {
	r.cacheMu.RLock()
	der, ok := r.verificationCAs[orgID]
	out := append([]byte(nil), der...)
	r.cacheMu.RUnlock()
	return out, ok
}

func (r *Repo) cacheCA(orgID uuid.UUID, der []byte) {
	r.cacheMu.Lock()
	if r.verificationCAs == nil {
		r.verificationCAs = make(map[uuid.UUID][]byte)
	}
	r.verificationCAs[orgID] = append([]byte(nil), der...)
	r.cacheMu.Unlock()
}

// PrimeVerificationCache authenticates existing public CA material before
// accepting runner traffic. A damaged organization's row is omitted and
// reported without denying healthy organizations. The callback receives only
// an organization ID; it must log a fixed error class, never the load error.
func (r *Repo) PrimeVerificationCache(ctx context.Context, report func(uuid.UUID)) error {
	rows, err := r.db.Query(ctx, `SELECT org_id FROM org_ca`)
	if err != nil {
		return errors.New("orgpki: list verification CAs failed")
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return errors.New("orgpki: read verification CAs failed")
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return errors.New("orgpki: read verification CAs failed")
	}
	verified := make(map[uuid.UUID][]byte, len(ids))
	for _, id := range ids {
		bundle, ok, err := r.load(ctx, id)
		if err != nil || !ok {
			if report != nil {
				report(id)
			}
			continue
		}
		verified[id] = append([]byte(nil), bundle.CACertDER...)
	}
	if len(ids) > 0 && len(verified) == 0 {
		return errors.New("orgpki: no existing organization CA authenticates")
	}
	r.cacheMu.Lock()
	r.verificationCAs = verified
	r.cacheMu.Unlock()
	return nil
}

// Validate refuses startup when an existing CA cannot be authenticated with
// the configured root. It does not generate or rewrite any key material.
func (r *Repo) Validate(ctx context.Context) error {
	rows, err := r.db.Query(ctx, `SELECT org_id FROM org_ca`)
	if err != nil {
		return fmt.Errorf("orgpki: list CAs: %w", err)
	}
	var orgs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		orgs = append(orgs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range orgs {
		if _, _, err := r.load(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repo) loadRecord(ctx context.Context, orgID uuid.UUID) (record, bool, error) {
	return loadRecordFrom(ctx, r.db, orgID)
}

func loadRecordFrom(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID uuid.UUID) (record, bool, error) {
	var rec record
	err := db.QueryRow(ctx, `SELECT ca_cert_der, sign_key_id, sign_pub_key,
 ca_kek_id, ca_wrapped_dek, ca_ciphertext, sign_kek_id, sign_wrapped_dek, sign_ciphertext
 FROM org_ca WHERE org_id=$1`, orgID).Scan(&rec.caCertDER, &rec.signKeyID, &rec.signPubKey,
		&rec.caEnv.KEKID, &rec.caEnv.WrappedDEK, &rec.caEnv.Ciphertext,
		&rec.signEnv.KEKID, &rec.signEnv.WrappedDEK, &rec.signEnv.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return record{}, false, nil
	}
	if err != nil {
		return record{}, false, fmt.Errorf("orgpki: load org CA: %w", err)
	}
	return rec, true, nil
}

func (r *Repo) load(ctx context.Context, orgID uuid.UUID) (Bundle, bool, error) {
	rec, ok, err := r.loadRecord(ctx, orgID)
	if err != nil || !ok {
		return Bundle{}, false, err
	}
	if err := r.authenticateBundle(ctx, orgID, rec); err != nil {
		return Bundle{}, false, err
	}
	return Bundle{CACertDER: rec.caCertDER, SignKeyID: rec.signKeyID, SignPubKey: ed25519.PublicKey(rec.signPubKey)}, true, nil
}

// Public verification keys are authenticated before they can become trust
// anchors. Open verifies the AEAD tags using the entire public material in
// the existing length-prefixed Ref context; its private result is wiped.
func (r *Repo) authenticateBundle(ctx context.Context, orgID uuid.UUID, rec record) error {
	v, err := r.sealer.Open(ctx, caRef(orgID, rec.caCertDER), rec.caEnv)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCAKeyMismatch, err)
	}
	v.Wipe()
	v, err = r.sealer.Open(ctx, signRef(orgID, rec.signKeyID, rec.signPubKey), rec.signEnv)
	if err != nil {
		return fmt.Errorf("orgpki: job-signing material does not authenticate: %w", err)
	}
	v.Wipe()
	return nil
}

// unsealCAKey reads the public context and envelope from the same row.
// The caller must wipe the returned private key immediately after use.
func (r *Repo) unsealCAKey(ctx context.Context, orgID uuid.UUID) ([]byte, error) {
	rec, ok, err := r.loadRecord(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrOrgNotFound
	}
	v, err := r.sealer.Open(ctx, caRef(orgID, rec.caCertDER), rec.caEnv)
	if err != nil {
		return nil, fmt.Errorf("orgpki: open CA envelope: %w", err)
	}
	defer v.Wipe()
	var out []byte
	secret.Expose(v, func(b []byte) { out = append([]byte(nil), b...) })
	return out, nil
}

// v2 is a pre-release org-PKI envelope format. Unauthenticated v1 draft
// rows fail closed; they must never be silently admitted as trust anchors.
// Hex encodes public bytes only, and separates the sign id from the key.
func caRef(orgID uuid.UUID, certDER []byte) sealer.Ref {
	return sealer.Ref{Store: sealer.Scope{Org: orgID.String(), PKI: true}, SecretID: "org-ca", Name: "private_key", Version: "v2:" + hex.EncodeToString(certDER)}
}
func signRef(orgID uuid.UUID, keyID string, pub []byte) sealer.Ref {
	return sealer.Ref{Store: sealer.Scope{Org: orgID.String(), PKI: true}, SecretID: "org-job-signing", Name: "private_key", Version: "v2:" + hex.EncodeToString([]byte(keyID)) + ":" + hex.EncodeToString(pub)}
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// wipe overwrites raw key bytes that are not a secret.Value — the same
// manual-zeroing convention internal/builtin/sealer's own rootkey.go uses
// for key material that isn't itself "a secret value" in the product
// sense, just key bytes this package generated and must not leave lying
// around in memory once sealed or once used.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation
}
