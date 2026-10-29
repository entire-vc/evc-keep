package tokenshape

import (
	"strings"
	"testing"
)

func TestContains(t *testing.T) {
	body := strings.Repeat("a2", 26) // 52 chars of the token alphabet
	for name, s := range map[string]string{
		"bare":        body,
		"prefixed":    "keep_a_" + body,
		"inside text": "failed for " + body + " twice",
		"upper case":  strings.ToUpper(body),
		"longer run":  body + "abc",
	} {
		if !Contains(s) {
			t.Errorf("%s: not recognized: %q", name, s)
		}
	}
	for name, s := range map[string]string{
		"empty":            "",
		"one short":        body[:51],
		"broken by hyphen": body[:26] + "-" + body[26:],
		"uuid":             "0190b0c2-7d1e-7a3b-9c4d-5e6f7a8b9c0d",
		"outside alphabet": strings.Repeat("a1", 26), // '1' is not base32
		"sha256 hex":       strings.Repeat("0123456789abcdef", 4),
	} {
		if Contains(s) {
			t.Errorf("%s: wrongly recognized: %q", name, s)
		}
	}
}

func TestRedact(t *testing.T) {
	body := strings.Repeat("a2", 26)
	got := string(Redact([]byte("x keep_a_"+body+" y "+body), []byte("[R]")))
	if strings.Contains(got, body) || got != "x keep_a_[R] y [R]" {
		t.Fatalf("Redact = %q", got)
	}
}

// TestRedactTakesTheWholeRun: a token's random part pressed against other
// characters of its own alphabet forms one longer run. Redacting only the
// first 52 characters of that run would leave the rest of the token in the
// output, up to 51 of its 52 characters, so the whole run must go.
func TestRedactTakesTheWholeRun(t *testing.T) {
	body := strings.Repeat("a2", 26)
	for k := 1; k < BodyLen; k++ {
		pad := strings.Repeat("z", k)
		for name, s := range map[string]string{
			"before": pad + body,
			"after":  body + pad,
			"both":   pad + body + pad,
		} {
			if got := string(Redact([]byte("x "+s+" y"), []byte("[R]"))); got != "x [R] y" {
				t.Fatalf("%s, %d adjacent characters: Redact = %q", name, k, got)
			}
		}
	}
}
