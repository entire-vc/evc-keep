//go:build unix

package runner

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Load reads a previously [Save]d Credential from dir. Every file must be a
// regular file (not a symlink), mode 0600 or tighter, and owned by the
// calling process's own user — exactly [ErrPolicy]'s check on the host
// policy file in pkg/runnerproto, applied here to the enrollment
// credential itself. keep-runner calls this before doing anything else at
// startup and exits if it fails: a private key readable by group or
// others is not a credential to start with, it is a credential to
// re-enroll after fixing the file (card's red-run test #5).
func Load(dir string) (Credential, error) {
	keyPEM, err := readSecureFile(filepath.Join(dir, keyFileName))
	if err != nil {
		return Credential{}, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return Credential{}, errors.New("runner: credential: malformed key file")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Credential{}, fmt.Errorf("runner: credential: parse key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return Credential{}, errors.New("runner: credential: key is not Ed25519")
	}

	certDER, err := readSecureFile(filepath.Join(dir, certFileName))
	if err != nil {
		return Credential{}, err
	}
	caCertDER, err := readSecureFile(filepath.Join(dir, caCertFileName))
	if err != nil {
		return Credential{}, err
	}
	signPubKey, err := readSecureFile(filepath.Join(dir, signPubKeyFileName))
	if err != nil {
		return Credential{}, err
	}
	signKeyID, err := readSecureFile(filepath.Join(dir, signKeyIDFileName))
	if err != nil {
		return Credential{}, err
	}
	host, err := readSecureFile(filepath.Join(dir, hostFileName))
	if err != nil {
		return Credential{}, err
	}
	deliveryBytes, err := readSecureFile(filepath.Join(dir, deliveryKeyFileName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Credential{}, err
	}
	var deliveryKey *ecdh.PrivateKey
	if err == nil {
		deliveryKey, err = ecdh.X25519().NewPrivateKey(deliveryBytes)
		clear(deliveryBytes)
		if err != nil {
			return Credential{}, errors.New("runner: credential: invalid delivery key")
		}
	}

	if len(signPubKey) != ed25519.PublicKeySize {
		return Credential{}, errors.New("runner: credential: org sign pub key has the wrong length")
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return Credential{}, fmt.Errorf("runner: credential: parse runner certificate: %w", err)
	}
	leafPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !leafPub.Equal(key.Public().(ed25519.PublicKey)) {
		return Credential{}, errors.New("runner: credential: runner certificate does not match the stored private key")
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return Credential{}, fmt.Errorf("runner: credential: parse pinned CA certificate: %w", err)
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		return Credential{}, fmt.Errorf("runner: credential: runner certificate does not chain to the pinned CA: %w", err)
	}

	return Credential{
		Key:         key,
		DeliveryKey: deliveryKey,
		CertDER:     certDER,
		CACertDER:   caCertDER,
		SignKeyID:   string(signKeyID),
		SignPubKey:  ed25519.PublicKey(signPubKey),
		Host:        string(host),
	}, nil
}

// readSecureFile requires a regular, non-symlinked file at path, mode 0600
// or tighter, owned by the calling process's own uid.
func readSecureFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: path is one of this package's own fixed credential filenames
	if err != nil {
		return nil, fmt.Errorf("runner: credential: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("runner: credential: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("runner: credential: %s is not a regular file", filepath.Base(path))
	case fi.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("runner: credential: %s must be mode 0600, refusing to start", filepath.Base(path))
	case !ok || int64(st.Uid) != int64(os.Getuid()):
		return nil, fmt.Errorf("runner: credential: %s is not owned by this user", filepath.Base(path))
	}
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
