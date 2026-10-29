package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
)

const (
	// tokenBytes is the amount of randomness in a generated token —
	// this package's own design decision: 32 bytes from crypto/rand.
	tokenBytes = 32
	// tokenPrefix is the fixed literal every Keep token starts with, so a
	// scanner (gitleaks — see .gitleaks.toml — or a human grepping a
	// leaked log) can recognize one on sight. Mirrors pkg/fingerprint's
	// own format-prefix reasoning.
	tokenPrefix = "keep"
)

// ErrMalformedToken is returned by [ParseKind] for anything that isn't
// shaped like a Keep token. It never includes the input — CONTRIBUTING.md:
// a secret-shaped value must never appear in an error.
var ErrMalformedToken = errors.New("identity: malformed token")

var (
	// b32 matches pkg/fingerprint's own encoding choice: unpadded,
	// lowercased after encoding (StdEncoding's alphabet is upper-case).
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	// tokenLen is the exact encoded length of tokenBytes of randomness:
	// ceil(32*8/5) = 52 base32 characters, no padding.
	tokenLen = (tokenBytes*8 + 4) / 5
	tokenRe  = regexp.MustCompile(fmt.Sprintf(`^keep_([asu])_([a-z2-7]{%d})$`, tokenLen))
)

// redacted is what every formatting path prints instead of a token.
const redacted = "[REDACTED]"

var errTokenNoDecode = errors.New("identity: Token cannot be decoded from text; use NewToken")

// Token is a Keep token's literal value: what a caller authenticates with,
// in the form "keep_<kind>_<base32(32 random bytes)>". It is a type of its
// own, not a string, so that redaction does not depend on where the value
// happens to be placed:
//
//   - every fmt verb, text/JSON encoding and slog value renders
//     [redacted];
//   - the text is held behind a pointer, because fmt reaches into a struct's
//     unexported fields by reflection and calls no method there — a plain
//     string (or a struct holding one) inside an unexported field prints
//     as itself, while a pointer at that depth prints as an address.
//
// The text comes out only through [Reveal], a function of this package, not
// a method of Token: a method can be reached through an interface or a
// generic constraint that only asks for a Reveal() string method, which
// forbidigo's analyze-types mode cannot see through (the type at the call
// site is the interface, not Token) — a package function has no such
// bypass, because there is no interface a caller could satisfy with it.
// Callers of Reveal are the few places that must use the value: hashing it,
// parsing its kind, and writing it once in an issuance response
// ([IssueResponse.WireJSON]).
type Token struct{ p *string }

// NewToken wraps text a caller presented (the Authorization header) or
// that was generated here.
func NewToken(text string) Token { return Token{p: &text} }

// Reveal returns a token's text. See [Token] for who may call it.
func Reveal(t Token) string {
	if t.p == nil {
		return ""
	}
	return *t.p
}

// IsZero reports whether t holds no text.
func (t Token) IsZero() bool { return t.p == nil || *t.p == "" }

func (Token) String() string               { return redacted }
func (Token) GoString() string             { return redacted }
func (Token) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }
func (Token) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Token) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Token) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (*Token) UnmarshalText([]byte) error  { return errTokenNoDecode }
func (*Token) UnmarshalJSON([]byte) error  { return errTokenNoDecode }

// GenerateToken returns a fresh token of the given kind: the literal value
// a caller authenticates with, in the form "keep_<kind>_<base32(32 random
// bytes)>" (this package's own design decision). It is returned to the caller of
// this function exactly as generated — see [Repo.Issue], the only place
// that is allowed to let it leave the process.
func GenerateToken(kind Kind) (Token, error) {
	if !kind.Valid() {
		return Token{}, fmt.Errorf("identity: invalid token kind %q", kind)
	}
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return Token{}, fmt.Errorf("identity: generate token: %w", err)
	}
	return NewToken(fmt.Sprintf("%s_%s_%s", tokenPrefix, kind, lower(b32.EncodeToString(b)))), nil
}

// ParseKind extracts the Kind from a token's own text, without touching
// the database — used to route an authentication lookup. It only checks
// shape, never whether the token exists, is expired, or is revoked; that
// is [Repo.Authenticate]'s job, and it fails exactly the same way to the
// caller as every other authentication failure (this package's own acceptance requirement).
func ParseKind(token Token) (Kind, error) {
	m := tokenRe.FindStringSubmatch(Reveal(token))
	if m == nil {
		return "", ErrMalformedToken
	}
	return Kind(m[1]), nil
}

// HashToken returns SHA-256(token) — the only form of a token this package
// ever writes to the database. See [Repo.Issue] and [Repo.Authenticate].
func HashToken(token Token) []byte {
	h := sha256.Sum256([]byte(Reveal(token)))
	return h[:]
}

// EqualHash does a constant-time comparison of two token hashes — used by
// [Repo.Authenticate] as a second check after the database's own indexed
// lookup, so the comparison that actually decides "is this the right
// token" never depends on SQL's `=` alone (this package's own design decision:
// subtle.ConstantTimeCompare).
func EqualHash(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Last4 returns a token's last four characters — safe to store and to
// show a holder which of their tokens a row is, never enough to
// reconstruct or narrow-search the rest (this package's own design decision).
func Last4(token Token) string {
	text := Reveal(token)
	if len(text) <= 4 {
		// Never hand back a value this short whole: for a malformed
		// input it could be all of it.
		return ""
	}
	return text[len(text)-4:]
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
