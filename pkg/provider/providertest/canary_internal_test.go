package providertest

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The detection algorithm and its alignment tests live in
// internal/testutil/canary. This only proves the suite's detector is that
// one: a leak behind a base64 prefix is seen, an unrelated canary is not.
func TestCanaryIn_UsesSharedDetector(t *testing.T) {
	c := newCanary()
	other := newCanary()

	for prefixLen := 0; prefixLen <= 2; prefixLen++ {
		prefix := strings.Repeat("x", prefixLen)
		leaked := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(prefix+"user:"+c.Value(1)))
		if !c.in(leaked) {
			t.Errorf("in() missed the canary at byte offset %d in standard base64", prefixLen)
		}
		urlLeak := base64.RawURLEncoding.EncodeToString([]byte(prefix + c.Value(1)))
		if !c.in(urlLeak) {
			t.Errorf("in() missed the canary at byte offset %d in URL-safe base64", prefixLen)
		}
		unrelated := base64.StdEncoding.EncodeToString([]byte(prefix + other.Value(1)))
		if c.in(unrelated) {
			t.Errorf("in() false-positived on an unrelated canary at offset %d", prefixLen)
		}
	}
}
