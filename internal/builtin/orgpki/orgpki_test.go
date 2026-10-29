package orgpki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// testDB opens a pool against a real, already-migrated PostgreSQL instance
// — CONTRIBUTING.md: the database layer is never mocked. Same convention as
// internal/identity's own testDB: it does not run migrations itself (see
// that package's doc for why — this test binary would race every other
// package's tests doing the same against one shared CI postgres service).
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedOrg(t *testing.T, db *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	if _, err := db.Exec(context.Background(), `INSERT INTO organizations (id, name) VALUES ($1, $2)`,
		id, "org-"+id.String()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return id
}

func newTestSealer(t *testing.T, db *pgxpool.Pool) *sealer.Sealer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("random root key: %v", err)
	}
	root, err := sealer.NewLocalRootKey("test-root", key)
	if err != nil {
		t.Fatalf("NewLocalRootKey: %v", err)
	}
	return sealer.New(root, noopAuditor{}, builtin.NewKeyStore(db))
}

func newRepo(t *testing.T) (*Repo, *pgxpool.Pool) {
	t.Helper()
	db := testDB(t)
	return NewRepo(db, newTestSealer(t, db)), db
}

// runnerCSR builds a self-signed Ed25519 CSR the way keep-runner enroll
// does: the runner's own keypair, with whatever Subject it likes — Subject
// is never trusted server-side (see [Repo.IssueRunnerCert]'s doc), so tests
// deliberately set one that does NOT match the real caller identity, to
// prove the server ignores it.
func runnerCSR(t *testing.T, subject pkix.Name) (csrDER []byte, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate runner key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: subject, PublicKey: pub}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der, priv
}

// ── Ensure ──────────────────────────────────────────────────────────────────

func TestEnsureGeneratesAndPersists(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)

	b1, err := repo.Ensure(context.Background(), org)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(b1.CACertDER) == 0 || len(b1.SignPubKey) != ed25519.PublicKeySize || b1.SignKeyID == "" {
		t.Fatalf("Ensure returned an incomplete bundle: %+v", b1)
	}
	caCert, err := x509.ParseCertificate(b1.CACertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	if !caCert.IsCA {
		t.Error("org CA certificate is not marked IsCA")
	}
	// MaxPathLenZero must be set so a bare zero MaxPathLen is actually
	// encoded (an unset MaxPathLen also parses back as 0), otherwise the CA
	// could certify intermediates able to certify further CAs.
	if caCert.MaxPathLen != 0 || !caCert.MaxPathLenZero {
		t.Errorf("org CA certificate MaxPathLen=%d MaxPathLenZero=%v, want 0/true so it cannot certify intermediate CAs", caCert.MaxPathLen, caCert.MaxPathLenZero)
	}
	if got := caCert.Subject.Organization; len(got) != 1 || got[0] != org.String() {
		t.Errorf("CA cert Subject.Organization = %v, want [%s]", got, org)
	}

	b2, err := repo.Ensure(context.Background(), org)
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if !bytes.Equal(b1.CACertDER, b2.CACertDER) || b1.SignKeyID != b2.SignKeyID || !bytes.Equal(b1.SignPubKey, b2.SignPubKey) {
		t.Error("second Ensure returned a different bundle — CA must be generated exactly once per organization")
	}
}

func TestEnsureConcurrentCallersConvergeOnOneCA(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)

	const n = 8
	bundles := make([]Bundle, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bundles[i], errs[i] = repo.Ensure(context.Background(), org)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Ensure[%d]: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if !bytes.Equal(bundles[0].CACertDER, bundles[i].CACertDER) || bundles[0].SignKeyID != bundles[i].SignKeyID {
			t.Fatalf("concurrent Ensure calls produced different CAs for the same org: [0]=%s [%d]=%s",
				bundles[0].SignKeyID, i, bundles[i].SignKeyID)
		}
	}

	var count int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM org_ca WHERE org_id = $1`, org).Scan(&count); err != nil {
		t.Fatalf("count org_ca rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("org_ca has %d rows for one organization, want 1", count)
	}
}

func TestEnsureRejectsUnknownOrg(t *testing.T) {
	repo, _ := newRepo(t)
	unknown := uuid.Must(uuid.NewV7())

	if _, err := repo.Ensure(context.Background(), unknown); err != ErrOrgNotFound {
		t.Fatalf("Ensure(unknown org) = %v, want ErrOrgNotFound", err)
	}
}

// ── IssueRunnerCert ──────────────────────────────────────────────────────────

func TestIssueRunnerCertSignsVerifiableCertIgnoringCSRSubject(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	runner := uuid.Must(uuid.NewV7())
	const host = "runner-1.example.test"

	otherOrg := uuid.Must(uuid.NewV7())
	otherRunner := uuid.Must(uuid.NewV7())
	csrDER, _ := runnerCSR(t, pkix.Name{
		// Deliberately claims a different org/runner/host than the real
		// caller-supplied identity below — the server must ignore every
		// bit of this.
		Organization: []string{otherOrg.String()},
		CommonName:   otherRunner.String(),
	})

	rc, err := repo.IssueRunnerCert(context.Background(), org, runner, host, csrDER)
	if err != nil {
		t.Fatalf("IssueRunnerCert: %v", err)
	}

	leaf, err := x509.ParseCertificate(rc.CertDER)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if got := leaf.Subject.Organization; len(got) != 1 || got[0] != org.String() {
		t.Errorf("issued cert Subject.Organization = %v, want [%s] (must come from the call, not the CSR)", got, org)
	}
	if leaf.Subject.CommonName != runner.String() {
		t.Errorf("issued cert CommonName = %q, want %q (must come from the call, not the CSR)", leaf.Subject.CommonName, runner)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != host {
		t.Errorf("issued cert DNSNames = %v, want [%s]", leaf.DNSNames, host)
	}

	caCert, err := x509.ParseCertificate(rc.CACertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("issued cert does not verify against its own org's CA: %v", err)
	}
}

func TestIssueRunnerCertRejectsMalformedCSR(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)

	if _, err := repo.IssueRunnerCert(context.Background(), org, uuid.Must(uuid.NewV7()), "h", []byte("not a csr")); err != ErrInvalidCSR {
		t.Fatalf("IssueRunnerCert(garbage CSR) = %v, want ErrInvalidCSR", err)
	}
}

func TestIssueRunnerCertRejectsTamperedSignature(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	csrDER, _ := runnerCSR(t, pkix.Name{CommonName: "x"})
	csrDER[len(csrDER)-1] ^= 0xFF // flip the last byte of the DER signature

	if _, err := repo.IssueRunnerCert(context.Background(), org, uuid.Must(uuid.NewV7()), "h", csrDER); err != ErrInvalidCSR {
		t.Fatalf("IssueRunnerCert(tampered CSR) = %v, want ErrInvalidCSR", err)
	}
}

func TestIssueRunnerCertRejectsNonEd25519Key(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, rsaPriv)
	if err != nil {
		t.Fatalf("create RSA CSR: %v", err)
	}

	if _, err := repo.IssueRunnerCert(context.Background(), org, uuid.Must(uuid.NewV7()), "h", der); err != ErrInvalidCSR {
		t.Fatalf("IssueRunnerCert(RSA CSR) = %v, want ErrInvalidCSR", err)
	}
}

// TestIssueRunnerCertRejectsSwappedCACertificate is the red-run for the
// tamper-detection check keep-crypto-reviewer asked for: a ca_cert_der row
// edited independently of the sealed CA private key (a DB write outside
// this package's own control) must fail issuance loudly, rather than
// silently minting a leaf certificate whose signature will never verify
// against the certificate anyone actually has. It asserts the specific
// ErrCAKeyMismatch, not just "any error" — x509.CreateCertificate also
// refuses a mismatched signing key on its own, so a bare err!=nil check
// would stay green even with the dedicated check mutated away (found by
// keep-crypto-reviewer's second pass).
func TestIssueRunnerCertRejectsSwappedCACertificate(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)
	ctx := context.Background()

	if _, err := repo.Ensure(ctx, org); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate replacement CA key: %v", err)
	}
	otherTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "swapped CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	swappedDER, err := x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, otherPub, otherPriv)
	if err != nil {
		t.Fatalf("create swapped CA cert: %v", err)
	}

	if _, err := db.Exec(ctx, `UPDATE org_ca SET ca_cert_der = $1 WHERE org_id = $2`, swappedDER, org); err != nil {
		t.Fatalf("swap ca_cert_der: %v", err)
	}

	csrDER, _ := runnerCSR(t, pkix.Name{CommonName: "x"})
	_, err = repo.IssueRunnerCert(ctx, org, uuid.Must(uuid.NewV7()), "h", csrDER)
	if err == nil {
		t.Fatal("IssueRunnerCert signed a certificate after ca_cert_der was swapped out from under the sealed CA key")
	}
	if !errors.Is(err, ErrCAKeyMismatch) {
		t.Fatalf("IssueRunnerCert(swapped ca_cert_der) = %v, want ErrCAKeyMismatch", err)
	}
}

// TestOrgCAEnvelopeNotOpenableAcrossOrgs is the card's cross-org isolation
// requirement (red-run #2), orgpki's own share of it: the CA private key's
// sealed envelope must be bound to the organization that owns it, not just
// stored in a row keyed by org_id. It replaces org A's entire org_ca row
// (certificate AND sealed envelope together, so the swapped-in key and cert
// are self-consistent — swapping only the envelope would be caught by the
// unrelated ca-pair check instead of the property under test) with org B's
// and requires that issuing under org A now fails, instead of silently
// signing with org B's key (crypto-review finding: no existing test
// exercised this — every test only ever sealed and opened under the same
// org).
func TestOrgCAEnvelopeNotOpenableAcrossOrgs(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)

	if _, err := repo.Ensure(ctx, orgA); err != nil {
		t.Fatalf("Ensure(A): %v", err)
	}
	if _, err := repo.Ensure(ctx, orgB); err != nil {
		t.Fatalf("Ensure(B): %v", err)
	}

	var caCertDER []byte
	var kekID string
	var wrappedDEK, ciphertext []byte
	if err := db.QueryRow(ctx, `SELECT ca_cert_der, ca_kek_id, ca_wrapped_dek, ca_ciphertext FROM org_ca WHERE org_id = $1`, orgB).
		Scan(&caCertDER, &kekID, &wrappedDEK, &ciphertext); err != nil {
		t.Fatalf("read org B's row: %v", err)
	}
	if _, err := db.Exec(ctx, `UPDATE org_ca SET ca_cert_der = $1, ca_kek_id = $2, ca_wrapped_dek = $3, ca_ciphertext = $4 WHERE org_id = $5`,
		caCertDER, kekID, wrappedDEK, ciphertext, orgA); err != nil {
		t.Fatalf("swap org A's row for org B's: %v", err)
	}

	csrDER, _ := runnerCSR(t, pkix.Name{CommonName: "x"})
	_, err := repo.IssueRunnerCert(ctx, orgA, uuid.Must(uuid.NewV7()), "h", csrDER)
	if err == nil {
		t.Fatal("IssueRunnerCert(org A) succeeded after org A's entire CA row was replaced with org B's — the sealed envelope is not bound to the organization that owns it")
	}
	if !errors.Is(err, sealer.ErrUnknownKEK) {
		t.Fatalf("IssueRunnerCert(org A) = %v, want an error wrapping sealer.ErrUnknownKEK (the org-binding check), not some other rejection", err)
	}
}

// ── leak test (card's red-run #4, package-internal half) ───────────────────

// TestCAPrivateKeyNeverLeaksThroughReturnValuesOrErrors is the white-box
// half of the card's canary requirement: it unseals the real, freshly
// generated CA private key (legitimate here only because this test lives
// inside package orgpki and needs ground truth to check against — no
// exported API does this) and then drives every exported entry point,
// success and failure alike, checking that key's bytes never surface in
// anything the package hands back: a Bundle, a RunnerCert, or an error's
// Error() string, under every fmt verb. The process-level half (stdout and
// stderr of the actual keep-server binary) lives in
// cmd/keep-server's own test suite, alongside keep-runner enroll's live
// round trip.
func TestCAPrivateKeyNeverLeaksThroughReturnValuesOrErrors(t *testing.T) {
	repo, db := newRepo(t)
	org := seedOrg(t, db)

	bundle, err := repo.Ensure(context.Background(), org)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	caKey, err := repo.unsealCAKey(context.Background(), org)
	if err != nil {
		t.Fatalf("unsealCAKey (test ground truth): %v", err)
	}
	defer wipe(caKey)
	// Two canaries — one over the key's hex text (catches %x and hex-string
	// leaks), one over the raw bytes (catches base64/percent/reversed
	// renderings of the raw bytes, e.g. a []byte field marshaled to JSON,
	// which base64-encodes the raw bytes, not their hex text). Neither form
	// of canary.In catches %v's decimal-list or %#v's Go-syntax rendering of
	// a []byte, so those two are checked directly below as well.
	c := canary.Of(hex.EncodeToString(caKey))
	cRaw := canary.Of(string(caKey))
	decimalRendering := fmt.Sprintf("%v", []byte(caKey))
	goSyntaxRendering := fmt.Sprintf("%#v", []byte(caKey))
	if !c.In(hex.EncodeToString(caKey)) || !cRaw.In(string(caKey)) {
		t.Fatal("canary detector does not recognize its own probe value — test is broken")
	}
	leaked := func(out string) bool {
		return c.In(out) || cRaw.In(out) ||
			strings.Contains(out, decimalRendering) || strings.Contains(out, goSyntaxRendering)
	}

	runner := uuid.Must(uuid.NewV7())
	goodCSR, _ := runnerCSR(t, pkix.Name{CommonName: "x"})
	badCSR := append([]byte(nil), goodCSR...)
	badCSR[len(badCSR)-1] ^= 0xFF

	rc, rcErr := repo.IssueRunnerCert(context.Background(), org, runner, "host.example.test", goodCSR)
	_, badErr := repo.IssueRunnerCert(context.Background(), org, runner, "host.example.test", badCSR)
	_, unknownOrgErr := repo.Ensure(context.Background(), uuid.Must(uuid.NewV7()))

	outputs := []string{
		fmt.Sprintf("%v", bundle), fmt.Sprintf("%+v", bundle), fmt.Sprintf("%#v", bundle),
		fmt.Sprintf("%v", rc), fmt.Sprintf("%+v", rc), fmt.Sprintf("%#v", rc),
	}
	for _, e := range []error{rcErr, badErr, unknownOrgErr} {
		if e != nil {
			outputs = append(outputs, e.Error(), fmt.Sprintf("%v", e), fmt.Sprintf("%+v", e))
		}
	}

	for i, out := range outputs {
		if leaked(out) {
			t.Fatalf("output #%d leaked the CA private key", i)
		}
	}
}

// A fresh root wrapper, Sealer and Repo must still sign using the persisted CA.
func TestIssueRunnerCert_PersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	org := seedOrg(t, db)
	rootBytes := make([]byte, 32)
	if _, err := rand.Read(rootBytes); err != nil {
		t.Fatal("generate root key")
	}
	defer clear(rootBytes)
	reopen := func() *Repo {
		repo, err := NewRepoFromKey(db, "restart-test-root", bytes.Clone(rootBytes))
		if err != nil {
			t.Fatal("construct repository")
		}
		return repo
	}
	first := reopen()
	bundle, err := first.Ensure(ctx, org)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	csr, _ := runnerCSR(t, pkix.Name{})
	for i := 0; i < 2; i++ {
		cert, err := reopen().IssueRunnerCert(ctx, org, uuid.New(), "runner.example.com", csr)
		if err != nil {
			t.Fatalf("issue after restart %d: %v", i, err)
		}
		if !bytes.Equal(cert.CACertDER, bundle.CACertDER) || !bytes.Equal(cert.SignPubKey, bundle.SignPubKey) {
			t.Fatal("pinned public material changed after restart")
		}
		leaf, err := x509.ParseCertificate(cert.CertDER)
		if err != nil {
			t.Fatal("parse issued certificate")
		}
		ca, err := x509.ParseCertificate(bundle.CACertDER)
		if err != nil {
			t.Fatal("parse CA certificate")
		}
		if err := leaf.CheckSignatureFrom(ca); err != nil {
			t.Fatal("reopened CA did not sign certificate")
		}
	}
}

// A provider key-level change may retire keys that also protect PKI rows.
// Purging those rows must fail closed while the CA still references them.
func TestOrgCAReferencedKEKCannotBePurged(t *testing.T) {
	repo, db := newRepo(t)
	ctx := context.Background()
	org := seedOrg(t, db)
	if _, err := repo.Ensure(ctx, org); err != nil {
		t.Fatal("initialize CA")
	}
	var caID, signID string
	if err := db.QueryRow(ctx, `SELECT ca_kek_id, sign_kek_id FROM org_ca WHERE org_id=$1`, org).Scan(&caID, &signID); err != nil {
		t.Fatal("read key references")
	}
	st := builtin.NewKeyStore(db)
	for _, id := range []string{caID, signID} {
		if err := st.Retire(ctx, org.String(), []string{id}); err != nil {
			t.Fatal("retire referenced key")
		}
		if err := st.Purge(ctx, org.String(), []string{id}); err == nil {
			t.Fatal("purge deleted a PKI-referenced key")
		}
	}
	csr, _ := runnerCSR(t, pkix.Name{})
	if _, err := repo.IssueRunnerCert(ctx, org, uuid.New(), "protected.example.test", csr); err != nil {
		t.Fatal("CA unavailable after rejected purge")
	}
}
