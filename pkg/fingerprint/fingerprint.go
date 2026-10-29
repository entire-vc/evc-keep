// Package fingerprint computes the only digest of a secret value Keep ever
// produces: a keyed, truncated HMAC that tells two carriers of the same value
// apart from carriers of a different one, without saying anything about the
// value to anyone who lacks the store's fingerprint key.
//
// Format (threat model, contract 4.1):
//
//	kfp1:<key_id>:<base32lower_nopad(HMAC-SHA256(key, "keep/fingerprint/v1" || 0x00 || value)[0:10])>
//
// The key is 32 random bytes, one per store, used for nothing else. The
// key_id names it, so rotating the key means recomputing the catalog. The
// 80-bit tag has no collisions within a store in practice, and without the
// key there is nothing to brute-force against.
//
// No other package may digest a plaintext value. The linter enforces it:
// secret.Expose is callable only from the packages that must see plaintext,
// and among those only this one may import a hash or MAC (see .golangci.yml,
// rules "plaintext-digest" and "expose-callers").
package fingerprint

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

const (
	// Prefix identifies the format version.
	Prefix = "kfp1"
	// KeySize is the fingerprint key length in bytes.
	KeySize = 32
	// TagBytes is the HMAC truncation length: 80 bits.
	TagBytes = 10

	domain = "keep/fingerprint/v1"
)

var (
	// ErrKeyID is returned for a key id outside [a-z0-9]{1,16}.
	ErrKeyID = errors.New("fingerprint: key id must be 1-16 characters of [a-z0-9]")
	// ErrKeySize is returned for key material that is not 32 bytes or is all zero.
	ErrKeySize = errors.New("fingerprint: key must be 32 bytes and not all zero")
	// ErrZeroKey is returned by Compute for a Key not built by NewKey or GenerateKey,
	// or already wiped: HMAC under it would be an unkeyed digest of the value.
	ErrZeroKey = errors.New("fingerprint: key is empty")
	// ErrMalformed is returned by Parse. It never includes the input.
	ErrMalformed = errors.New("fingerprint: malformed")
)

var (
	keyIDRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	// 10 bytes are exactly 16 base32 characters, so there is no padding to strip.
	formatRe = regexp.MustCompile(`^kfp1:([a-z0-9]{1,16}):([a-z2-7]{16})$`)
	b32      = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Key is a store's fingerprint key. Like secret.Value, every formatting path
// renders it without its bytes; only the id is shown.
type Key struct {
	id string
	b  []byte
}

// NewKey copies b into a Key named id. The caller should wipe its own copy.
func NewKey(id string, b []byte) (Key, error) {
	if !keyIDRe.MatchString(id) {
		return Key{}, ErrKeyID
	}
	if len(b) != KeySize || allZero(b) {
		return Key{}, ErrKeySize
	}
	c := make([]byte, KeySize)
	copy(c, b)
	return Key{id: id, b: c}, nil
}

// GenerateKey returns a new random Key named id.
func GenerateKey(id string) (Key, error) {
	if !keyIDRe.MatchString(id) {
		return Key{}, ErrKeyID
	}
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return Key{}, fmt.Errorf("fingerprint: generate key: %w", err)
	}
	return Key{id: id, b: b}, nil
}

// ID returns the key id.
func (k Key) ID() string { return k.id }

// ExposeKey calls fn with the key bytes, for the sealer to wrap under a KEK.
// fn must not retain the slice. Like secret.Expose it is a package function,
// so it cannot be reached through an interface the linter does not see.
func ExposeKey(k Key, fn func([]byte)) { fn(k.b) }

// Wipe overwrites the key bytes.
func (k Key) Wipe() {
	for i := range k.b {
		k.b[i] = 0
	}
}

// Compute returns the fingerprint of v under k.
func Compute(k Key, v secret.Value) (string, error) {
	if len(k.b) != KeySize || allZero(k.b) {
		return "", ErrZeroKey
	}
	m := hmac.New(sha256.New, k.b)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	secret.Expose(v, func(b []byte) { m.Write(b) })
	return Prefix + ":" + k.id + ":" + lower(b32.EncodeToString(m.Sum(nil)[:TagBytes])), nil
}

// Parsed is a fingerprint split into its fields.
type Parsed struct {
	KeyID string
	Tag   string
}

// Parse splits a fingerprint. The error never includes the input.
func Parse(s string) (Parsed, error) {
	m := formatRe.FindStringSubmatch(s)
	if m == nil {
		return Parsed{}, ErrMalformed
	}
	return Parsed{KeyID: m[1], Tag: m[2]}, nil
}

// Valid reports whether s is a well-formed fingerprint.
func Valid(s string) bool { return formatRe.MatchString(s) }

func (k Key) String() string               { return "fingerprint.Key(" + k.id + ")" }
func (k Key) GoString() string             { return k.String() }
func (k Key) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(k.String())) }
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }
func (k Key) MarshalJSON() ([]byte, error) { return []byte(`"` + k.String() + `"`), nil }
func (k Key) LogValue() slog.Value         { return slog.StringValue(k.String()) }
func (*Key) UnmarshalText([]byte) error    { return errNoDecode }
func (*Key) UnmarshalJSON([]byte) error    { return errNoDecode }

var errNoDecode = errors.New("fingerprint.Key cannot be decoded from text; use NewKey")

func allZero(b []byte) bool {
	return subtle.ConstantTimeCompare(b, make([]byte, len(b))) == 1
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
