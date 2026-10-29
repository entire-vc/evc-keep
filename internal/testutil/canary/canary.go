// Package canary gives tests a value that must never surface in a log line,
// a response body, or an error's text, and a way to check whether it did —
// across the encodings a value might accidentally survive through on its
// way out (a header, a JSON string, a URL query, …).
//
// This is a temporary, standalone copy: pkg/provider/providertest (not yet
// merged into main) carries the canonical version of this helper for
// provider conformance tests. Once that lands, this package is meant to be
// reconciled with it rather than living on in parallel.
package canary

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// Canary is a per-test random value plus the machinery to check for it.
type Canary struct{ base string }

// New generates a fresh canary. Call it once per test — a shared canary
// across tests would let one test's leak mask as another's false negative.
func New() Canary {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return Canary{base: "kc" + hex.EncodeToString(b)}
}

// Value returns the i-th canary value; every value contains the base, so
// checking for the base via In catches any of them.
func (c Canary) Value(i int) string {
	return fmt.Sprintf("%s-v%d-secret", c.base, i)
}

// Of wraps an existing string as a Canary, for probing a value the test
// doesn't control the bytes of — a real token minted by the package under
// test, say — instead of one New generated itself. In detects it across
// the same encodings and base64 alignments a New-generated value is
// detected in; it just isn't guaranteed random or unique the way New's
// output is, so a caller with a choice of which value to use should still
// prefer New.
//
// Of probes the string it is given and nothing else. A value with a
// recognizable prefix (a token's "keep_a_") is leaked just as fully by its
// remainder alone, which Of(whole) never matches: probe that part with its
// own Of as well.
func Of(s string) Canary {
	return Canary{base: s}
}

// In reports whether s contains the canary in any common encoding: raw,
// hex, base64 (standard and URL-safe), percent-encoded, or reversed. A
// leak rarely survives as the exact original bytes — this is the set of
// encodings it checks.
func (c Canary) In(s string) bool {
	if s == "" {
		return false
	}
	for _, enc := range c.encodings() {
		if strings.Contains(s, enc) || strings.Contains(strings.ToLower(s), strings.ToLower(enc)) {
			return true
		}
	}
	return false
}

func (c Canary) encodings() []string {
	raw := []byte(c.base)
	out := []string{
		c.base,
		hex.EncodeToString(raw),
		url.QueryEscape(c.base),
		reverse(c.base),
	}
	out = append(out, base64Alignments(raw, base64.StdEncoding)...)
	out = append(out, base64Alignments(raw, base64.RawURLEncoding)...)
	return out
}

// base64Alignments returns the substrings of raw's base64 encoding that are
// safe to search for regardless of where raw's first byte falls within a
// larger encoded buffer.
//
// Base64 groups bytes three at a time. A real leak rarely encodes raw in
// isolation — e.g. `Authorization: Basic ` + base64("user:"+value) — so
// raw's first byte can land at any of three positions (its index mod 3)
// within its 3-byte group, and each position produces a DIFFERENT run of
// characters for the bytes straddling raw's boundary, because those
// characters also encode bits from the unknown neighboring byte(s).
// Checking only the offset-0 alignment (the original bug: encoding raw on
// its own always starts a fresh group) is blind to the other two.
//
// For each of the three possible offsets, this re-encodes raw prefixed
// with `offset` placeholder bytes, then keeps only the run of characters
// that comes from whole groups made ENTIRELY of raw's own bytes — never a
// group straddling the placeholder/raw or raw/(whatever follows) boundary,
// since that group's characters depend on bytes we don't and can't know.
// The placeholder's actual value is therefore irrelevant; it's discarded,
// never compared.
func base64Alignments(raw []byte, enc *base64.Encoding) []string {
	var out []string
	for offset := 0; offset <= 2; offset++ {
		padded := make([]byte, offset, offset+len(raw))
		padded = append(padded, raw...)
		encoded := enc.EncodeToString(padded)

		firstPureGroup := (offset + 2) / 3   // ceil(offset/3)
		groupsEnd := (offset + len(raw)) / 3 // floor((offset+len(raw))/3)
		if groupsEnd <= firstPureGroup {
			continue // raw too short at this offset to yield a whole clean group
		}
		out = append(out, encoded[4*firstPureGroup:4*groupsEnd])
	}
	return out
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
