// Package runner holds keep-runner's own on-host state: the mTLS client
// credential issued at enrollment (its private key, its certificate, the
// organization's CA it was enrolled under, and the organization's
// job-signing public key pinned at that same moment — ADR-001 §3.2: the
// runner pins the organization's CA and job-signing key it received at
// registration. It is zone-internals protected: reachable only from the
// plaintext zone and cmd/keep-runner, mirroring internal/builtin's own
// boundary for cmd/keep-server.
package runner

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	keyFileName         = "runner_key.pem"
	deliveryKeyFileName = "runner_delivery.key"
	certFileName        = "runner_cert.der"
	caCertFileName      = "org_ca.der"
	signPubKeyFileName  = "org_sign_pub.key"
	signKeyIDFileName   = "org_sign_key_id"
	hostFileName        = "host"
)

// Credential is everything keep-runner needs to authenticate to Keep
// Server over mTLS and to verify a signed job without asking the server
// again.
type Credential struct {
	Key         ed25519.PrivateKey
	DeliveryKey *ecdh.PrivateKey
	CertDER     []byte
	CACertDER   []byte
	SignKeyID   string
	SignPubKey  ed25519.PublicKey
	Host        string
}

// String, GoString, Format, MarshalJSON and LogValue all redact Key (and the
// DER-encoded certificate material) so a stray log line, %v, %+v, %#v,
// json.Marshal or a slog handler logging a Credential directly never prints
// the private key bytes. encoding/json and log/slog each dispatch to their
// own interface instead of falling back to struct-tag reflection, so
// Marshaler/LogValuer must be implemented explicitly — fmt's Stringer alone
// does not cover them.
func (c Credential) String() string {
	return fmt.Sprintf("Credential{Host:%s, SignKeyID:%s, Key:[REDACTED]}", c.Host, c.SignKeyID)
}

func (c Credential) GoString() string { return c.String() }

func (c Credential) Format(f fmt.State, verb rune) { _, _ = fmt.Fprint(f, c.String()) }

func (c Credential) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Host      string `json:"host"`
		SignKeyID string `json:"sign_key_id"`
		Key       string `json:"key"`
	}{Host: c.Host, SignKeyID: c.SignKeyID, Key: "[REDACTED]"})
}

func (c Credential) LogValue() slog.Value { return slog.StringValue(c.String()) }

// Save writes c under dir as a set of individually 0600 files, creating
// dir (mode 0700) if it does not exist yet, and tightening it to 0700 if it
// already exists wider. Load (credential_unix.go) refuses to read any of
// these files back if their mode has widened or their owner has changed
// since — the card's red-run test #5. Each file is written via a temp file
// plus rename so re-enrolling into a directory that already holds a
// wide-mode or symlinked file never writes key material through it.
func Save(dir string, c Credential) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil { //nolint:gosec // G301: the credential dir's *parent* (e.g. ~/.keep), not the credential dir itself — ensureSecureDir below tightens the credential dir to 0700
		return fmt.Errorf("runner: credential dir parent: %w", err)
	}
	if err := ensureSecureDir(dir); err != nil {
		return fmt.Errorf("runner: credential dir: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return fmt.Errorf("runner: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if c.DeliveryKey != nil && c.DeliveryKey.Curve() != ecdh.X25519() {
		return errors.New("runner: delivery key must be X25519")
	}
	var deliveryBytes []byte
	if c.DeliveryKey != nil {
		deliveryBytes = c.DeliveryKey.Bytes()
		defer clear(deliveryBytes)
	}

	writes := []struct {
		name string
		data []byte
	}{
		{keyFileName, keyPEM},
		{certFileName, c.CertDER},
		{caCertFileName, c.CACertDER},
		{signPubKeyFileName, c.SignPubKey},
		{signKeyIDFileName, []byte(c.SignKeyID)},
		{hostFileName, []byte(c.Host)},
	}
	if c.DeliveryKey != nil {
		writes = append(writes, struct {
			name string
			data []byte
		}{deliveryKeyFileName, deliveryBytes})
	}
	for _, w := range writes {
		if err := writeSecureFile(filepath.Join(dir, w.name), w.data); err != nil {
			return fmt.Errorf("runner: write %s: %w", w.name, err)
		}
	}
	if c.DeliveryKey == nil {
		if err := os.Remove(filepath.Join(dir, deliveryKeyFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("runner: remove legacy delivery key: %w", err)
		}
	}
	return nil
}

// ensureSecureDir makes dir exist as a real (non-symlink) directory at mode
// 0700, tightening its mode if it already exists wider. It refuses a dir
// path that is a symlink or not a directory rather than writing through it.
func ensureSecureDir(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.Mkdir(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential dir %s is a symlink", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("credential dir %s is not a directory", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: tightening an existing credential dir to 0700, not widening it
			return err
		}
	}
	return nil
}

// writeSecureFile writes data to path atomically: a temp file created 0600
// in the same directory, fsynced, then renamed over path. rename(2) never
// follows a symlink at the destination — it replaces the directory entry
// itself — so an existing wide-mode file or a planted symlink at path never
// receives key material; Load (credential_unix.go) sees only the fresh file.
func writeSecureFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-runner-cred-*") //nolint:gosec // G304: dir is this package's own fixed credential dir
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
