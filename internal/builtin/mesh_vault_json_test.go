package builtin

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

// appendJSONString writes the value into the resolve answer by hand, so it
// must produce valid JSON that decodes to the same text, for any text.
func TestAppendJSONStringRoundTrips(t *testing.T) {
	cases := []string{"", "plain", `"`, `\`, `x","version":"evil`, "a\nb\r\tc", "\x00\x01\x1f\x7f", "</script>&", "日本語🔑", "  "}
	// Every rune below 0x250, in sliding windows of varying width.
	var all []rune
	for r := rune(0); r < 0x250; r++ {
		all = append(all, r)
	}
	for start := 0; start < len(all); start += 7 {
		for _, width := range []int{1, 5, 40} {
			end := min(start+width, len(all))
			cases = append(cases, string(all[start:end]))
		}
	}
	for _, in := range cases {
		out := appendJSONString(nil, []byte(in))
		var got string
		if err := json.Unmarshal(out, &got); err != nil || got != in {
			t.Fatalf("%q encoded as %q decoded as %q (%v)", in, out, got, err)
		}
	}
}

// Bytes that are not UTF-8 never produce invalid JSON, and never grow the
// output past the 6-bytes-per-byte bound the caller sizes its buffer by.
func TestAppendJSONStringBadBytesStayValidAndBounded(t *testing.T) {
	in := []byte{0xff, 0xfe, 'a', 0xc3, 0x28, 0xe2, 0x82}
	out := appendJSONString(nil, in)
	// json.Unmarshal silently repairs bad bytes, so check the raw output.
	if !utf8.Valid(out) {
		t.Fatalf("invalid bytes passed through raw: %q", out)
	}
	var got string
	if err := json.Unmarshal(out, &got); err != nil || !utf8.ValidString(got) {
		t.Fatalf("invalid bytes produced %q (%v)", out, err)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if out := appendJSONString(nil, all); len(out) > 6*len(all)+2 {
		t.Fatalf("output %d bytes for %d input bytes", len(out), len(all))
	}
}
