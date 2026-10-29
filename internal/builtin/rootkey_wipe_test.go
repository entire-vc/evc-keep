package builtin

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestRootBuffersWiped(t *testing.T) {
	raw := bytes.Repeat([]byte{'*'}, 32)
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))
	defer clear(raw)
	defer clear(encoded)
	for _, tc := range []struct {
		name  string
		input []byte
		valid bool
	}{
		{"raw", raw, true},
		{"base64", encoded, true},
		{"decode-error", append(bytes.Clone(encoded[:40]), []byte("!!!!")...), false},
		{"invalid-length", []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'*'}, 33))), false},
		{"ambiguous", []byte(base64.StdEncoding.EncodeToString(raw[:24])), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := bytes.Clone(tc.input)
			key := make([]byte, max(32, base64.StdEncoding.DecodedLen(len(input))))
			consumed := false
			local, err := openLocalEncoded(input, key, func(k []byte) (*Local, error) {
				consumed = true
				if !bytes.Equal(k, raw) {
					t.Error("decoded root control failed")
				}
				return NewLocal(nil, "test-root", k, nil, nopAudit)
			})
			if tc.valid != (err == nil && local != nil) || consumed != tc.valid {
				t.Fatal("root outcome control failed")
			}
			if !bytes.Equal(input, make([]byte, len(input))) {
				t.Error("encoded root buffer was not wiped")
			}
			if !bytes.Equal(key, make([]byte, len(key))) {
				t.Error("decoded root buffer was not wiped")
			}
		})
	}
}
