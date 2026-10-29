package sealer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
)

// RootKey wraps KEKs. Production implementations call a KMS, Vault Transit
// or OpenBao; the key never leaves it. LocalRootKey is for self-hosted
// installations without a KMS, with the key in its own file (ADR-001 §5).
type RootKey interface {
	// ID names the root key; it is stored next to every wrapped KEK so the
	// root key can be rotated.
	ID() string
	Wrap(plain, aad []byte) ([]byte, error)
	Unwrap(wrapped, aad []byte) ([]byte, error)
}

// ErrUnwrap is returned when a wrapped key or a ciphertext does not
// authenticate: wrong key, wrong AAD or tampered bytes. It carries no detail.
var ErrUnwrap = errors.New("sealer: authentication failed")

type localRootKey struct {
	id   string
	aead cipher.AEAD
}

// NewLocalRootKey returns a RootKey backed by a 32-byte AES key held in
// memory. The caller should wipe its copy of key.
func NewLocalRootKey(id string, key []byte) (RootKey, error) {
	var nonzero byte
	for _, b := range key {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, errors.New("sealer: root key must be nonzero")
	}
	a, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &localRootKey{id: id, aead: a}, nil
}

func (r *localRootKey) ID() string { return r.id }

func (r *localRootKey) Wrap(plain, aad []byte) ([]byte, error) { return seal(r.aead, plain, aad) }

func (r *localRootKey) Unwrap(wrapped, aad []byte) ([]byte, error) { return open(r.aead, wrapped, aad) }

var errKeySize = errors.New("sealer: key must be 32 bytes")

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errKeySize
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, errKeySize
	}
	return cipher.NewGCM(b)
}

// seal returns nonce || ciphertext.
func seal(a cipher.AEAD, plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, a.NonceSize(), a.NonceSize()+len(plain)+a.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plain, aad), nil
}

func open(a cipher.AEAD, b, aad []byte) ([]byte, error) {
	if len(b) < a.NonceSize() {
		return nil, ErrUnwrap
	}
	p, err := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], aad)
	if err != nil {
		return nil, ErrUnwrap
	}
	return p, nil
}

func randomKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// aad builds unambiguous associated data: a domain label followed by
// length-prefixed fields, so ("ab","c") and ("a","bc") never collide.
func aad(label string, fields ...string) []byte {
	b := make([]byte, 0, 64)
	b = append(b, label...)
	for _, f := range fields {
		n := len(f)
		if n > math.MaxUint32 {
			panic("sealer: aad field too long")
		}
		b = binary.BigEndian.AppendUint32(b, uint32(n))
		b = append(b, f...)
	}
	return b
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
