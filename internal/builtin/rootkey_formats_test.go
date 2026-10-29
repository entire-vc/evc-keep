package builtin

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestRootKeyFormatsAndClosedErrors(t *testing.T) {
	c := canary.New()
	raw := []byte(c.Value(1))[:32]
	defer clear(raw)
	base64Expected := bytes.Clone(raw)
	defer clear(base64Expected)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	defer clear(encoded)
	// Successfully decoded but invalid lengths exercise the second error
	// branch. Each fixture retains the canary, unlike zero-filled keys.
	decoded := []byte(c.Value(1))
	defer clear(decoded)
	invalidBase64 := func(size int) []byte {
		content := make([]byte, base64.StdEncoding.EncodedLen(size))
		base64.StdEncoding.Encode(content, decoded[:size])
		t.Cleanup(func() { clear(content) })
		if !c.In(string(decoded[:size])) || !c.In(string(content)) {
			t.Fatal("invalid-length root canary detector is blind")
		}
		return content
	}
	// Raw bytes must never be trimmed: key bytes can themselves be whitespace.
	raw[0], raw[31] = ' ', '\n'
	probe := canary.Of(string(raw))
	if !probe.In(string(raw)) || !c.In(c.Value(1)) {
		t.Fatal("root canary detector is blind")
	}
	ambiguous := []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 24)))
	for name, content := range map[string][]byte{"raw": raw, "base64": encoded, "base64-24-ambiguous": ambiguous, "base64-31": invalidBase64(31), "base64-33": invalidBase64(33), "invalid": []byte(c.Value(1)), "short": raw[:31], "zero": make([]byte, 32), "oversized": make([]byte, 1024)} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "root")
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal("write fixture")
			}
			local, err := OpenLocalFile(nil, path, "test-root", nil, nopAudit)
			if err != nil && (c.In(err.Error()) || probe.In(err.Error())) {
				t.Fatal("root material leaked through error")
			}
			// The canary detector does not cover short key fragments.
			if err != nil && strings.Contains(err.Error(), string(content[:min(12, len(content))])) {
				t.Fatal("root prefix leaked through error")
			}
			valid := name == "raw" || name == "base64"
			if valid && (err != nil || local == nil) {
				t.Fatal("valid root format rejected")
			}
			expected := content
			if name == "base64" {
				expected = base64Expected
			}
			if valid {
				observed := false
				encodedCopy := bytes.Clone(content)
				key := make([]byte, max(32, base64.StdEncoding.DecodedLen(len(content))))
				_, err := openLocalEncoded(encodedCopy, key, func(raw []byte) (*Local, error) {
					observed = true
					if !bytes.Equal(raw, expected) {
						t.Error("root format changed")
					}
					return NewLocal(nil, "test-root", raw, nil, nopAudit)
				})
				if err != nil || !observed {
					t.Fatal("root observation control failed")
				}
			}
			if !valid && (err == nil || local != nil) {
				t.Fatal("invalid root accepted")
			}
			if err != nil && strings.Contains(err.Error(), string(decoded[:12])) {
				t.Fatal("decoded root prefix leaked through error")
			}

		})
	}
}
