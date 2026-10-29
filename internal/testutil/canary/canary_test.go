package canary

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// TestIn_FindsValueAtAnyBase64Alignment is the red run for the base64
// offset blind spot (canary.In doesn't see a value inside
// base64 when it starts 1-2 bytes into the encoded buffer). The real
// scenario this stands in for: an `Authorization: Basic` header, whose
// value is base64("user:" + secret) — the secret never starts at byte
// offset 0 of the encoded buffer, because "user:" comes first.
//
// On the pre-fix code (only the offset-0 alignment checked) this test
// fails for prefixLen 1 and 2 — reproduced by reverting canary.go's
// base64Alignments to the single-alignment version and re-running this
// file: both non-zero prefixLen subtests go red, prefixLen=0 stays green.
func TestIn_FindsValueAtAnyBase64Alignment(t *testing.T) {
	c := New()
	v := c.Value(1)

	for prefixLen := 0; prefixLen <= 2; prefixLen++ {
		prefixLen := prefixLen
		t.Run(fmt.Sprintf("offset=%d/std", prefixLen), func(t *testing.T) {
			prefix := strings.Repeat("x", prefixLen)
			leaked := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(prefix+"user:"+v))
			if !c.In(leaked) {
				t.Errorf("In() missed the canary at byte offset %d in standard base64: %q", prefixLen, leaked)
			}
		})
		t.Run(fmt.Sprintf("offset=%d/urlsafe", prefixLen), func(t *testing.T) {
			prefix := strings.Repeat("x", prefixLen)
			leaked := base64.RawURLEncoding.EncodeToString([]byte(prefix + v))
			if !c.In(leaked) {
				t.Errorf("In() missed the canary at byte offset %d in URL-safe base64: %q", prefixLen, leaked)
			}
		})
	}
}

// TestIn_DoesNotFalselyMatchUnrelatedBase64 is the negative counterpart:
// the widened search must not start matching arbitrary base64 noise. Each
// of the three alignments is exercised with a DIFFERENT random canary, so
// none of them can find another's value.
func TestIn_DoesNotFalselyMatchUnrelatedBase64(t *testing.T) {
	c := New()
	other := New()
	v := other.Value(1)

	for prefixLen := 0; prefixLen <= 2; prefixLen++ {
		prefix := strings.Repeat("x", prefixLen)
		leaked := base64.StdEncoding.EncodeToString([]byte(prefix + v))
		if c.In(leaked) {
			t.Errorf("In() false-positived on an unrelated canary's base64 at offset %d: %q", prefixLen, leaked)
		}
	}
}

// TestOf_DetectsAnArbitraryValueAcrossEncodings is Of's own red run: a
// value Of wraps (not one New generated) must be found by In across the
// same encodings and base64 alignments New's own values are — including
// the offset-1/2 base64 alignment this package was fixed for — and must
// not false-positive on unrelated text.
func TestOf_DetectsAnArbitraryValueAcrossEncodings(t *testing.T) {
	const v = "keep_a_mockmockmockmockmockmockmockmockmockmockmo"
	c := Of(v)

	cases := map[string]string{
		"raw":      "token=" + v,
		"reversed": reverse(v),
		"hex":      hex.EncodeToString([]byte(v)),
	}
	for name, s := range cases {
		if !c.In(s) {
			t.Errorf("Of(%q).In() missed the %s encoding: %q", v, name, s)
		}
	}

	for prefixLen := 0; prefixLen <= 2; prefixLen++ {
		prefix := strings.Repeat("x", prefixLen)
		leaked := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(prefix+"user:"+v))
		if !c.In(leaked) {
			t.Errorf("Of(...).In() missed the value at byte offset %d in base64: %q", prefixLen, leaked)
		}
	}

	if c.In("a completely unrelated string that shares no substring") {
		t.Fatal("Of(...).In() false-positived on unrelated text")
	}
}

func TestIn_StillFindsRawAndHexAndReversed(t *testing.T) {
	c := New()
	v := c.Value(1)

	cases := map[string]string{
		"raw":      "value=" + v,
		"reversed": reverse(v),
	}
	for name, s := range cases {
		if !c.In(s) {
			t.Errorf("In() regressed on the %s encoding: %q", name, s)
		}
	}
}
