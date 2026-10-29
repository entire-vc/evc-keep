package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCredential builds a Credential backed by a real, self-consistent
// certificate chain — a self-signed CA and a leaf it actually signed for
// the runner's own key — so Load's chain and public-key checks
// (credential_unix.go) pass on it exactly as they would on a genuine
// enrollment, not just on well-formed-looking placeholder bytes.
func testCredential(t *testing.T) Credential {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test org CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate runner key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-runner"},
		DNSNames:              []string{"runner.example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, pub, caPriv)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	signPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sign key: %v", err)
	}

	return Credential{
		Key:        priv,
		CertDER:    certDER,
		CACertDER:  caCertDER,
		SignKeyID:  "org-v1",
		SignPubKey: signPub,
		Host:       "runner.example.test",
	}
}

func TestSaveLoadCredentialRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := testCredential(t)
	if err := Save(dir, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Host != want.Host || got.SignKeyID != want.SignKeyID {
		t.Fatalf("round trip mismatch: got %+v", got)
	}
	if string(got.CertDER) != string(want.CertDER) || string(got.CACertDER) != string(want.CACertDER) {
		t.Fatal("certificate material did not round trip")
	}
	if !want.Key.Public().(ed25519.PublicKey).Equal(got.Key.Public().(ed25519.PublicKey)) {
		t.Fatal("private key did not round trip")
	}
}

// TestLoadCredentialRefusesWideKeyPermissions is the card's red-run test
// #5: a runner key file with mode 0644 must refuse to load, not silently
// start with a group/world-readable private key.
func TestLoadCredentialRefusesWideKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	cred := testCredential(t)
	if err := Save(dir, cred); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Positive control: the check can pass before proving it can fail.
	if _, err := Load(dir); err != nil {
		t.Fatalf("positive control: %v", err)
	}

	if err := os.Chmod(filepath.Join(dir, keyFileName), 0o644); err != nil { //nolint:gosec // G302: the test needs a too-open file
		t.Fatalf("chmod: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("runner started with a world-readable key file (mode 0644)")
	}
}

func TestLoadCredentialRefusesGroupReadableKey(t *testing.T) {
	dir := t.TempDir()
	cred := testCredential(t)
	if err := Save(dir, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, keyFileName), 0o640); err != nil { //nolint:gosec // G302: the test needs a too-open file
		t.Fatalf("chmod: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("runner started with a group-readable key file (mode 0640)")
	}
}

func TestLoadCredentialRefusesSymlinkedKey(t *testing.T) {
	dir := t.TempDir()
	cred := testCredential(t)
	if err := Save(dir, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	real := filepath.Join(dir, keyFileName)
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.pem")
	if err := os.Rename(real, elsewhere); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.Chmod(elsewhere, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := os.Symlink(elsewhere, real); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("runner started with a symlinked key file")
	}
}

// TestLoadCredentialRefusesCertKeyMismatch is a red-run for the pub-key
// match check added to Load: a certificate that doesn't belong to the
// stored private key must never be accepted, however well-formed its own
// chain is.
func TestLoadCredentialRefusesCertKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	cred := testCredential(t)
	other := testCredential(t)
	cred.CertDER = other.CertDER
	cred.CACertDER = other.CACertDER
	if err := Save(dir, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a certificate that does not match the stored private key")
	}
}

// TestLoadCredentialRefusesCertNotChainedToCA is a red-run for the chain
// check added to Load: a leaf certificate for the right key, but signed by
// a different CA than the one pinned alongside it, must be rejected.
func TestLoadCredentialRefusesCertNotChainedToCA(t *testing.T) {
	dir := t.TempDir()
	cred := testCredential(t)
	other := testCredential(t)
	cred.CACertDER = other.CACertDER // wrong CA for cred's own CertDER
	if err := Save(dir, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a runner certificate that does not chain to the pinned CA")
	}
}

// TestLoadCredentialRefusesWrongLengthSignPubKey is a red-run for the
// length check added to Load: ed25519.Verify panics on a public key that
// isn't exactly 32 bytes, so a truncated or corrupted org sign key must be
// rejected before it ever reaches a verifier.
func TestLoadCredentialRefusesWrongLengthSignPubKey(t *testing.T) {
	dir := t.TempDir()
	cred := testCredential(t)
	cred.SignPubKey = cred.SignPubKey[:16]
	if err := Save(dir, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted an org sign pub key of the wrong length")
	}
}

func TestLoadCredentialRefusesMissingFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("runner started with no credential at all")
	}
}

// TestSaveRewritesExistingWideModeFile is a red-run for writeSecureFile: a
// re-enroll into a directory that already holds a widened key file (e.g.
// left over from an operator recovering after the #5 refusal above) must
// not write the new key into that same wide-mode file.
func TestSaveRewritesExistingWideModeFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, keyFileName)
	if err := os.WriteFile(keyPath, []byte("stale"), 0o644); err != nil { //nolint:gosec // G302: the test needs a too-open pre-existing file
		t.Fatalf("seed stale file: %v", err)
	}

	if err := Save(dir, testCredential(t)); err != nil {
		t.Fatalf("save: %v", err)
	}

	fi, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode after Save = %o, want 0600", fi.Mode().Perm())
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("load after re-save: %v", err)
	}
}

// TestSaveDoesNotWriteThroughSymlinkedKeyFile is a red-run for
// writeSecureFile: a symlink planted at the key file's path must not
// receive the new key material at its target.
func TestSaveDoesNotWriteThroughSymlinkedKeyFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "planted-target.pem")
	if err := os.WriteFile(target, []byte("planted"), 0o600); err != nil {
		t.Fatalf("seed planted target: %v", err)
	}
	keyPath := filepath.Join(dir, keyFileName)
	if err := os.Symlink(target, keyPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := Save(dir, testCredential(t)); err != nil {
		t.Fatalf("save: %v", err)
	}

	targetData, err := os.ReadFile(target) //nolint:gosec // G304: target is this test's own fixture path
	if err != nil {
		t.Fatalf("read planted target: %v", err)
	}
	if string(targetData) != "planted" {
		t.Fatal("Save wrote key material through a symlink to a file outside the credential dir")
	}
	fi, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatalf("stat key path: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("Save left the symlink in place instead of replacing it with a real file")
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("load after save over symlink: %v", err)
	}
}

// TestSaveTightensExistingWideDirectory is a red-run for ensureSecureDir: a
// credential dir left at a wider mode by a previous version or an operator
// mistake must be tightened back to 0700, not left readable by others.
func TestSaveTightensExistingWideDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the test needs a too-open pre-existing directory
		t.Fatalf("chmod dir: %v", err)
	}

	if err := Save(dir, testCredential(t)); err != nil {
		t.Fatalf("save: %v", err)
	}

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("credential dir mode after Save = %o, want 0700", fi.Mode().Perm())
	}
}

// TestSaveRefusesSymlinkedDirectory is a red-run for ensureSecureDir: the
// credential dir path itself must not be a symlink to somewhere else.
func TestSaveRefusesSymlinkedDirectory(t *testing.T) {
	real := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "cred-link")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := Save(linkDir, testCredential(t)); err == nil {
		t.Fatal("Save accepted a symlinked credential directory")
	}
}
