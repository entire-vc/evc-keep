package reqid

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestFromHeaderRefusesATokenBody: the id a client sends is echoed into a
// response header and every log line of the request, so a value long enough
// to hold a token's random part (52 base32 characters) must be replaced,
// not reused.
func TestFromHeaderRefusesATokenBody(t *testing.T) {
	body := strings.Repeat("a2", 26)
	for name, v := range map[string]string{
		"token body":       body,
		"full token":       "keep_a_" + body,
		"one over the cap": strings.Repeat("a", 37),
		"empty":            "",
		"header injection": "abc\r\nSet-Cookie: x=y",
		"format directive": "%s%n",
		"space":            "a b",
		"non-ASCII":        "r\u00e9q-\u4e2d",
	} {
		got := FromHeader(v)
		if got == v {
			t.Errorf("%s: %q was reused", name, v)
		}
		if _, err := uuid.Parse(got); err != nil {
			t.Errorf("%s: replacement %q is not a fresh UUID", name, got)
		}
	}
}

// TestFromHeaderKeepsASafeID is the control for the test above: refusing
// everything would pass it too.
func TestFromHeaderKeepsASafeID(t *testing.T) {
	for _, v := range []string{uuid.NewString(), "a", strings.Repeat("A", 36), "trace-42"} {
		if got := FromHeader(v); got != v {
			t.Errorf("safe id %q was replaced with %q", v, got)
		}
	}
}

func TestNewIsFreshUUIDv7(t *testing.T) {
	a, b := New(), New()
	if a == b {
		t.Fatalf("New returned the same id twice: %s", a)
	}
	u, err := uuid.Parse(a)
	if err != nil || u.Version() != 7 {
		t.Fatalf("New = %q, want a UUIDv7 (err %v)", a, err)
	}
}

func TestContextRoundTrip(t *testing.T) {
	if got := FromContext(context.Background()); got != "" {
		t.Fatalf("empty context carries %q", got)
	}
	if got := FromContext(WithContext(context.Background(), "abc")); got != "abc" {
		t.Fatalf("FromContext = %q, want abc", got)
	}
}
