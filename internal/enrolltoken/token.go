// Package enrolltoken is the one-time, host- and policy-bound token an
// organization admin issues (`keep runner enroll-token`) so a new runner can
// bootstrap itself (`keep-runner enroll`). ADR-001 §3.2 ("Registration"),
// threat model §2.3 (S, E).
//
// A token's literal text exists outside this package exactly once — in the
// IssueResponse [Repo.Issue] returns — the same convention internal/identity's
// tokens use, and for the same reason: only the token's SHA-256 hash is ever
// written to the database (internal/store/migrations/00008_runner_enroll.sql,
// enroll_tokens.token_hash).
package enrolltoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
)

const (
	// tokenBytes is the amount of randomness in a generated token — this
	// package's own design decision, matching internal/identity's: 32
	// bytes from crypto/rand.
	tokenBytes = 32
	// tokenPrefix is the fixed literal every token starts with, so a
	// scanner (gitleaks — see .gitleaks.toml's keep-runner-enroll-token
	// rule) or a human grepping a leaked log recognizes one on sight.
	tokenPrefix = "keep_renr_" //nolint:gosec // G101: a literal format prefix, not a credential value
)

var (
	// b32 matches internal/identity's own encoding choice: unpadded,
	// lowercased after encoding (StdEncoding's alphabet is upper-case).
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	// tokenLen is the exact encoded length of tokenBytes of randomness:
	// ceil(32*8/5) = 52 base32 characters, no padding.
	tokenLen = (tokenBytes*8 + 4) / 5
)

// redacted is what every formatting path prints instead of a token.
const redacted = "[REDACTED]"

var errTokenNoDecode = errors.New("enrolltoken: Token cannot be decoded from text; use NewToken")

// Token is an enrollment token's literal value, in the form
// "keep_renr_<base32(32 random bytes)>". It is a type of its own, not a
// string, for exactly the reason internal/identity.Token is one — see that
// type's doc:
//
//   - every fmt verb, text/JSON encoding and slog value renders [redacted];
//   - the text is held behind a pointer, because fmt reaches into a struct's
//     unexported fields by reflection and calls no method there.
//
// The text comes out only through [Token.Reveal]: hashing it (Issue),
// looking it up (Redeem), and writing it once into an issuance response
// ([IssueResponse.WireJSON]).
type Token struct{ p *string }

// NewToken wraps text a caller presented (a keep-runner enroll request body)
// or that was generated here.
func NewToken(text string) Token { return Token{p: &text} }

// Reveal returns the token's text. See [Token] for who may call it.
func (t Token) Reveal() string {
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

// GenerateToken returns a fresh token: the literal value a runner presents
// to redeem it, in the form "keep_renr_<base32(32 random bytes)>". It is
// returned exactly as generated only to [Repo.Issue], the sole place allowed
// to let it leave the process.
func GenerateToken() (Token, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return Token{}, fmt.Errorf("enrolltoken: generate token: %w", err)
	}
	return NewToken(tokenPrefix + lower(b32.EncodeToString(b))), nil
}

// HashToken returns SHA-256(token) — the only form of a token this package
// ever writes to the database. See [Repo.Issue] and [Repo.Redeem].
func HashToken(token Token) []byte {
	h := sha256.Sum256([]byte(token.Reveal()))
	return h[:]
}

// EqualHash does a constant-time comparison of two token hashes — used by
// [Repo.Redeem] as a second check after the database's own indexed lookup,
// so the comparison that actually decides "is this the right token" never
// depends on SQL's `=` alone. Mirrors internal/identity.EqualHash.
func EqualHash(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Last4 returns a token's last four characters — safe to store and to show
// an admin which of the tokens they issued a row is, never enough to
// reconstruct or narrow-search the rest.
func Last4(token Token) string {
	text := token.Reveal()
	if len(text) <= 4 {
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
