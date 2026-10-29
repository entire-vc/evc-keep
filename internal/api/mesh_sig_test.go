package api

import (
	"bytes"
	"strings"
	"testing"
)

// TestMeshEventSigShape pins the closed form of an event's X-Mesh-Signature:
// exactly 64 lowercase hex characters, bare (Mesh's documented form) or after
// one "v1=". Everything else is refused before any MAC is computed.
func TestMeshEventSigShape(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	want := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	for name, h := range map[string]string{"bare": hex64, "v1 prefix": "v1=" + hex64} {
		got, ok := meshEventSig(h)
		if !ok || len(got) != 32 || !bytes.Equal(got[:8], want) {
			t.Errorf("%s: meshEventSig = %x, %v; want 32 decoded bytes, true", name, got, ok)
		}
	}
	for name, h := range map[string]string{
		"empty":            "",
		"prefix only":      "v1=",
		"63 chars":         hex64[:63],
		"65 chars":         hex64 + "0",
		"62 chars":         hex64[:62],
		"66 chars":         hex64 + "00",
		"v1 prefix 62":     "v1=" + hex64[:62],
		"v1 prefix 66":     "v1=" + hex64 + "00",
		"uppercase":        strings.ToUpper(hex64),
		"one upper":        "A" + hex64[1:],
		"double prefix":    "v1=v1=" + hex64,
		"double prefix 64": "v1=v1=" + hex64[:61], // 64 characters after one prefix is stripped
		"other prefix":     "v2=" + hex64,
		"sha256 prefix":    "sha256=" + hex64,
		"upper prefix":     "V1=" + hex64,
		"leading space":    " " + hex64,
		"trailing space":   hex64[:63] + " ",
		"not hex":          strings.Repeat("zz", 32),
		"comma list":       hex64[:31] + "," + hex64[:32],
	} {
		if got, ok := meshEventSig(h); ok || got != nil {
			t.Errorf("%s: meshEventSig(%q) = %x, %v; want refusal", name, h, got, ok)
		}
	}
}
