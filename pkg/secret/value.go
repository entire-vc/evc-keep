// Package secret holds the only type in Keep that carries a plaintext secret
// value. Every formatting path renders it as [REDACTED]; the raw bytes are
// reachable only through Expose, whose callers are restricted by the linter
// (.golangci.yml, rule expose-callers) to the plaintext zone: this package,
// pkg/fingerprint, pkg/provider, internal/builtin, internal/runner and
// internal/targets.
//
// Expose is a package function, not a method, on purpose: a method can be
// reached through a caller-declared interface or a generic constraint, where
// the linter no longer sees secret.Value; a package function can only be
// named as secret.Expose.
package secret

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
)

// Redacted is what every formatting path prints instead of the value.
const Redacted = "[REDACTED]"

// Value is a plaintext secret. The zero Value is empty.
//
// A Value must never be converted to string for transport, logging or
// comparison. Use Expose to hand the bytes to the code that consumes them.
type Value struct {
	b []byte
}

// New copies b into a new Value. The caller should Wipe its own copy.
func New(b []byte) Value {
	c := make([]byte, len(b))
	copy(c, b)
	return Value{b: c}
}

// Len returns the length of the value in bytes. Length is allowed metadata.
func (v Value) Len() int { return len(v.b) }

// IsZero reports whether the value is empty.
func (v Value) IsZero() bool { return len(v.b) == 0 }

// Expose calls fn with the raw bytes of v. fn must not retain the slice.
func Expose(v Value, fn func([]byte)) { fn(v.b) }

// Equal compares two values in constant time.
func (v Value) Equal(o Value) bool {
	return len(v.b) == len(o.b) && subtle.ConstantTimeCompare(v.b, o.b) == 1
}

// Wipe overwrites the underlying bytes. Copies made by Clone are unaffected.
func (v Value) Wipe() {
	for i := range v.b {
		v.b[i] = 0
	}
}

// Clone returns an independent copy.
func (v Value) Clone() Value { return New(v.b) }

func (Value) String() string               { return Redacted }
func (Value) GoString() string             { return Redacted }
func (Value) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(Redacted)) }
func (Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }
func (Value) LogValue() slog.Value         { return slog.StringValue(Redacted) }
func (*Value) UnmarshalText([]byte) error  { return errNoDecode }
func (*Value) UnmarshalJSON([]byte) error  { return errNoDecode }

var errNoDecode = fmt.Errorf("secret.Value cannot be decoded from text; use secret.New")
