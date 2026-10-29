package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const canary = "keep-canary-7f3a9c1e-value"

// TestValueNeverFormats is the guard for contract 4.4 of the threat model:
// no formatting path may print the plaintext.
func TestValueNeverFormats(t *testing.T) {
	v := New([]byte(canary))

	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("x", "v", v, "ptr", &v)
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("x", "v", v)

	js, err := json.Marshal(struct {
		V Value
		P *Value
	}{v, &v})
	if err != nil {
		t.Fatal(err)
	}

	outputs := map[string]string{
		"%v":      fmt.Sprintf("%v", v),
		"%+v":     fmt.Sprintf("%+v", v),
		"%#v":     fmt.Sprintf("%#v", v),
		"%s":      fmt.Sprintf("%s", v),
		"%q":      fmt.Sprintf("%q", v),
		"%x":      fmt.Sprintf("%x", v),
		"%X":      fmt.Sprintf("%X", v),
		"%d":      fmt.Sprintf("%d", v),
		"ptr %v":  fmt.Sprintf("%v", &v),
		"ptr %+v": fmt.Sprintf("%+v", &v),
		"struct":  fmt.Sprintf("%+v", struct{ V Value }{v}),
		"error":   fmt.Errorf("wrap: %v", v).Error(),
		"json":    string(js),
		"slog":    logBuf.String(),
	}
	for name, out := range outputs {
		if leaks(out) {
			t.Errorf("%s leaked the value: %q", name, out)
		}
		if !strings.Contains(out, Redacted) {
			t.Errorf("%s did not print the redaction marker: %q", name, out)
		}
	}
}

// TestLeakDetectorCanFail proves the detector above is not vacuous.
func TestLeakDetectorCanFail(t *testing.T) {
	var raw string
	Expose(New([]byte(canary)), func(b []byte) { raw = string(b) })
	if !leaks("prefix " + raw + " suffix") {
		t.Fatal("leak detector did not flag the raw value")
	}
	if !leaks(fmt.Sprintf("%x", raw)) {
		t.Fatal("leak detector did not flag the hex-encoded value")
	}
}

func leaks(s string) bool {
	return strings.Contains(s, canary) || strings.Contains(s, fmt.Sprintf("%x", canary))
}

func TestValueSemantics(t *testing.T) {
	a := New([]byte("abc"))
	if a.Len() != 3 || a.IsZero() {
		t.Fatal("len")
	}
	if !a.Equal(New([]byte("abc"))) || a.Equal(New([]byte("abd"))) {
		t.Fatal("equal")
	}
	c := a.Clone()
	a.Wipe()
	Expose(a, func(b []byte) {
		if !bytes.Equal(b, []byte{0, 0, 0}) {
			t.Fatal("wipe")
		}
	})
	Expose(c, func(b []byte) {
		if string(b) != "abc" {
			t.Fatal("clone not independent")
		}
	})
	var v Value
	if err := json.Unmarshal([]byte(`"x"`), &v); !errors.Is(err, errNoDecode) {
		t.Fatalf("decode must be refused, got %v", err)
	}
}
