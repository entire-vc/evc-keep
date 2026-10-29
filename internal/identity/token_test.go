package identity

import (
	"regexp"
	"testing"

	"github.com/entire-vc/evc-keep/internal/tokenshape"
)

func TestGenerateTokenRoundTripsThroughParseKind(t *testing.T) {
	for _, k := range []Kind{KindAgent, KindService, KindUser} {
		token, err := GenerateToken(k)
		if err != nil {
			t.Fatalf("GenerateToken(%q): %v", k, err)
		}
		if !gitleaksTokenRegex.MatchString(Reveal(token)) {
			t.Fatalf("generated kind %q token does not match .gitleaks.toml's keep-identity-token rule", k)
		}
		got, err := ParseKind(token)
		if err != nil {
			t.Fatalf("ParseKind(kind %q): %v", k, err)
		}
		if got != k {
			t.Errorf("ParseKind(kind %q) = %q, want %q", k, got, k)
		}
	}
}

func TestGenerateTokenRejectsInvalidKind(t *testing.T) {
	if _, err := GenerateToken(Kind("x")); err == nil {
		t.Fatal("expected an error for an invalid kind")
	}
}

func TestParseKindRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-token",
		"keep_x_" + Reveal(mustToken(t, KindAgent))[7:], // valid body, invalid kind letter
		"keep_a_tooshort",
		"KEEP_a_" + Reveal(mustToken(t, KindAgent))[7:], // wrong case prefix
	}
	for _, c := range cases {
		if _, err := ParseKind(NewToken(c)); err == nil {
			t.Errorf("ParseKind(%q): expected ErrMalformedToken, got nil", c)
		}
	}
}

func TestGenerateTokenIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		token, err := GenerateToken(KindAgent)
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if seen[Reveal(token)] {
			t.Fatal("GenerateToken produced a repeat")
		}
		seen[Reveal(token)] = true
	}
}

func TestHashTokenIsDeterministicAndNotTheToken(t *testing.T) {
	token := mustToken(t, KindAgent)
	h1 := HashToken(token)
	h2 := HashToken(token)
	if !EqualHash(h1, h2) {
		t.Fatal("HashToken is not deterministic")
	}
	if string(h1) == Reveal(token) {
		t.Fatal("hash equals the plaintext token — sha256.Sum256 must have been bypassed")
	}
	if len(h1) != 32 {
		t.Fatalf("hash length = %d, want 32 (SHA-256)", len(h1))
	}
}

func TestEqualHashRejectsDifferentHashes(t *testing.T) {
	a := HashToken(mustToken(t, KindAgent))
	b := HashToken(mustToken(t, KindAgent))
	if EqualHash(a, b) {
		t.Fatal("EqualHash reported two different tokens' hashes as equal")
	}
}

func TestLast4(t *testing.T) {
	token := mustToken(t, KindService)
	last4 := Last4(token)
	if len(last4) != 4 {
		t.Fatalf("Last4 length = %d, want 4", len(last4))
	}
	if text := Reveal(token); last4 != text[len(text)-4:] {
		t.Fatalf("Last4 = %q, want the literal last 4 characters", last4)
	}
	// Last4 must not be enough to search-narrow the rest: it names no
	// more than 4 of the token's 52 random characters.
	if len(last4) >= tokenLen {
		t.Fatal("Last4 reveals the whole random portion of the token")
	}
}

// gitleaksTokenRegex mirrors .gitleaks.toml's keep-identity-token rule
// exactly, so TestGenerateTokenRoundTripsThroughParseKind can assert the
// scanner's own regex — not just this package's internal one — matches
// what GenerateToken actually produces. Any drift between the two would
// mean a real token wouldn't be caught by the scanner even though this
// package's own parser accepts it.
var gitleaksTokenRegex = regexp.MustCompile(`keep_[asu]_[a-z2-7]{52}`)

func mustToken(t *testing.T, k Kind) Token {
	t.Helper()
	token, err := GenerateToken(k)
	if err != nil {
		t.Fatalf("GenerateToken(%q): %v", k, err)
	}
	return token
}

// TestTokenshapeAgreesWithGeneratedTokens: internal/obs and internal/reqid
// blank or refuse anything shaped like a token's random part using
// tokenshape's own pattern and length, without importing this package. If
// GenerateToken's output ever stops matching that pattern, those guards
// would quietly stop covering real tokens.
func TestTokenshapeAgreesWithGeneratedTokens(t *testing.T) {
	if tokenshape.BodyLen != tokenLen {
		t.Fatalf("tokenshape.BodyLen = %d, but a token's random part is %d characters", tokenshape.BodyLen, tokenLen)
	}
	for _, k := range []Kind{KindAgent, KindService, KindUser} {
		text := Reveal(mustToken(t, k))
		body := text[len("keep_a_"):]
		if !tokenshape.Contains(body) {
			t.Errorf("tokenshape does not recognize the random part of a generated kind %q token", k)
		}
		if got := string(tokenshape.Redact([]byte(text), []byte("X"))); got != text[:len("keep_a_")]+"X" {
			t.Errorf("tokenshape.Redact left part of a kind %q token: %q", k, got)
		}
	}
}

func TestLast4NeverReturnsAShortInputWhole(t *testing.T) {
	for _, in := range []string{"", "a", "abcd"} {
		if got := Last4(NewToken(in)); got != "" {
			t.Errorf("Last4(%q) = %q, want empty for an input of 4 characters or fewer", in, got)
		}
	}
}
