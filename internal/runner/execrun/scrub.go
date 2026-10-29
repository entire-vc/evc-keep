// Package execrun runs an approved exec_with_secret template on the host:
// it re-validates the template against the host policy, builds the child's
// environment from nothing, cuts the child off the network where the OS
// allows, and scrubs what the child prints. The scrubber is insurance, not
// the boundary: a command that sends the value over the network prints
// nothing, so isolation is what stops that, and the scrubber only catches the
// accidental echo.
package execrun

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"sort"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

const redacted = "[REDACTED]"

// scrubber knows the value in the encodings an echo may take. It holds
// derived copies of the value, so it is built per run and wiped after.
type scrubber struct {
	needles [][]byte
	// b64 are the base64 runs: around one, the groups that hold the value's
	// first and last bytes share their characters with bytes that are not the
	// value's, so the replacement also takes the four characters on each side.
	b64 [][]byte
}

func newScrubber(v secret.Value) *scrubber {
	s := &scrubber{}
	secret.Expose(v, func(raw []byte) {
		if len(raw) == 0 {
			return
		}
		add := func(b []byte) {
			if len(b) > 0 {
				s.needles = append(s.needles, append([]byte(nil), b...))
			}
		}
		add(raw)
		lower := hex.EncodeToString(raw)
		add([]byte(lower))
		add([]byte(string(bytes.ToUpper([]byte(lower)))))
		add([]byte(url.QueryEscape(string(raw))))
		add([]byte(url.PathEscape(string(raw))))
		rev := make([]byte, len(raw))
		for i := range raw {
			rev[len(raw)-1-i] = raw[i]
		}
		add(rev)
		// Whole groups carry no padding, so the padded alphabets add nothing.
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			for _, a := range base64Alignments(raw, enc) {
				add([]byte(a))
				s.b64 = append(s.b64, []byte(a))
			}
		}
	})
	// Longest first, so a form that contains a shorter one is replaced whole.
	sort.SliceStable(s.needles, func(i, j int) bool { return len(s.needles[i]) > len(s.needles[j]) })
	return s
}

// base64Alignments returns the runs of raw's base64 text that do not depend
// on the bytes around raw: the value's first byte can fall at any of three
// positions in a 3-byte group, and only whole groups made of its own bytes
// are the same wherever it sits.
func base64Alignments(raw []byte, enc *base64.Encoding) []string {
	var out []string
	for offset := 0; offset <= 2; offset++ {
		padded := make([]byte, offset, offset+len(raw))
		padded = append(padded, raw...)
		text := enc.EncodeToString(padded)
		first := (offset + 2) / 3
		end := (offset + len(raw)) / 3
		if end <= first {
			continue
		}
		out = append(out, text[4*first:4*end])
	}
	return out
}

func (s *scrubber) maxNeedle() int {
	if len(s.needles) == 0 {
		return 0
	}
	return len(s.needles[0])
}

// Scrub returns the captured output with every form of the value replaced by
// [REDACTED], cut to at most limit bytes. more says the capture itself was cut
// short (bytes were dropped after it): then, after the replacement, the last
// maxNeedle-1 bytes are dropped, because they could be the start of a form
// whose end is gone.
// Replacement is done on the whole capture before any cut to limit, so a value
// that straddles the limit is replaced, not halved. If the value only shows
// once line breaks are removed (wrapped base64), the whole output is withheld.
// The bool reports whether output was cut.
func (s *scrubber) Scrub(captured []byte, more bool, limit int) (string, bool) {
	res := append([]byte(nil), captured...)
	for _, n := range s.b64 {
		res = replaceWithEdges(res, n)
	}
	for _, n := range s.needles {
		res = bytes.ReplaceAll(res, n, []byte(redacted))
	}
	if more {
		// A form the capture cut in half is still here, as a prefix at the
		// very end; it is shorter than the longest form, so it is within
		// the last maxNeedle-1 bytes.
		// Eight more: the edge characters a base64 run takes with it.
		keep := len(res) - (s.maxNeedle() - 1 + 8)
		if keep < 0 {
			keep = 0
		}
		res = res[:keep]
	}
	if s.hiddenByBreaks(res) {
		return redacted, more
	}
	truncated := more
	if limit >= 0 && len(res) > limit {
		res, truncated = res[:limit], true
	}
	return string(res), truncated
}

// hiddenByBreaks reports whether a form of the value appears in out once
// line breaks and blanks are taken out, which is how `base64` wraps its text.
func (s *scrubber) hiddenByBreaks(out []byte) bool {
	flat := bytes.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		}
		return r
	}, out)
	if len(flat) == len(out) {
		return false
	}
	for _, n := range s.needles {
		if bytes.Contains(flat, n) {
			return true
		}
	}
	return false
}

// Wipe overwrites the derived copies of the value.
func (s *scrubber) Wipe() {
	for _, n := range s.needles {
		clear(n)
	}
	for _, n := range s.b64 {
		clear(n)
	}
	s.needles, s.b64 = nil, nil
}

func isB64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_'
}

// replaceWithEdges replaces every n in b by the marker, together with up to
// four base64 characters just before and just after it.
func replaceWithEdges(b, n []byte) []byte {
	var out []byte
	for {
		i := bytes.Index(b, n)
		if i < 0 {
			return append(out, b...)
		}
		start, end := i, i+len(n)
		for k := 0; k < 4 && start > 0 && isB64Char(b[start-1]); k++ {
			start--
		}
		for k := 0; k < 4 && end < len(b) && isB64Char(b[end]); k++ {
			end++
		}
		out = append(out, b[:start]...)
		out = append(out, redacted...)
		b = b[end:]
	}
}
