package providertest

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestCanaryIn_FindsValueAtAnyBase64Alignment is the red run for this
// package's own copy of the base64 offset blind spot (see
// canaryBase64Alignments' doc comment, and internal/testutil/canary for
// the canonical writeup of the same fix). The real scenario this stands
// in for: an `Authorization: Basic` header, whose value is
// base64("user:" + secret) — the secret never starts at byte offset 0 of
// the encoded buffer, because "user:" comes first.
//
// On the pre-fix code (only the offset-0 alignment checked) this test
// fails for non-zero offsets — reproduced by reverting encodings() to
// the single-alignment version and re-running this file.
func TestCanaryIn_FindsValueAtAnyBase64Alignment(t *testing.T) {
	c := newCanary()
	// c.value(i) wraps this same string in secret.Value for use through
	// the provider API; here we need the plaintext directly to build a
	// leaked-looking string, so reproduce it rather than unwrap a Value
	// (which would need secret.Expose, restricted to the plaintext zone).
	v := fmt.Sprintf("%s-v1-secret", c.base)

	for prefixLen := 0; prefixLen <= 2; prefixLen++ {
		prefixLen := prefixLen
		t.Run(fmt.Sprintf("offset=%d/std", prefixLen), func(t *testing.T) {
			prefix := strings.Repeat("x", prefixLen)
			leaked := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(prefix+"user:"+v))
			if !c.in(leaked) {
				t.Errorf("in() missed the canary at byte offset %d in standard base64: %q", prefixLen, leaked)
			}
		})
		t.Run(fmt.Sprintf("offset=%d/urlsafe", prefixLen), func(t *testing.T) {
			prefix := strings.Repeat("x", prefixLen)
			leaked := base64.RawURLEncoding.EncodeToString([]byte(prefix + v))
			if !c.in(leaked) {
				t.Errorf("in() missed the canary at byte offset %d in URL-safe base64: %q", prefixLen, leaked)
			}
		})
	}
}

func TestCanaryIn_DoesNotFalselyMatchUnrelatedBase64(t *testing.T) {
	c := newCanary()
	other := newCanary()
	v := fmt.Sprintf("%s-v1-secret", other.base)

	for prefixLen := 0; prefixLen <= 2; prefixLen++ {
		prefix := strings.Repeat("x", prefixLen)
		leaked := base64.StdEncoding.EncodeToString([]byte(prefix + v))
		if c.in(leaked) {
			t.Errorf("in() false-positived on an unrelated canary's base64 at offset %d: %q", prefixLen, leaked)
		}
	}
}
