package execrun

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func scrubOf(t *testing.T, value string, out string, limit int) (string, bool) {
	t.Helper()
	v := secret.New([]byte(value))
	s := newScrubber(v)
	// What Run does: the pipe keeps limit+maxNeedle bytes, the rest is dropped.
	captured, more := []byte(out), false
	if room := limit + s.maxNeedle(); len(captured) > room {
		captured, more = captured[:room], true
	}
	return s.Scrub(captured, more, limit)
}

func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// A command that prints the value in any of the encodings the canary knows
// must show [REDACTED] and no trace of the value.
func TestScrubRemovesEveryEncoding(t *testing.T) {
	c := canary.New()
	val := c.Value(1)
	forms := map[string]string{
		"raw":        val,
		"hex":        hex.EncodeToString([]byte(val)),
		"hex-upper":  strings.ToUpper(hex.EncodeToString([]byte(val))),
		"b64":        base64.StdEncoding.EncodeToString([]byte(val)),
		"b64-raw":    base64.RawStdEncoding.EncodeToString([]byte(val)),
		"b64url":     base64.RawURLEncoding.EncodeToString([]byte(val)),
		"b64-shift1": base64.StdEncoding.EncodeToString([]byte("a" + val)),
		"b64-shift2": base64.StdEncoding.EncodeToString([]byte("ab" + val + "z")),
		"query":      url.QueryEscape(val),
		"reversed":   reverseStr(val),
	}
	for name, form := range forms {
		out, _ := scrubOf(t, val, "before "+form+" after\n", 1<<16)
		if c.In(out) {
			t.Errorf("%s: value survived the scrub: %q", name, out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("%s: no [REDACTED] marker in %q", name, out)
		}
		if !strings.HasPrefix(out, "before ") {
			t.Errorf("%s: scrub damaged the surrounding output: %q", name, out)
		}
	}
}

// Positive control: the same detector sees the value in unscrubbed output,
// so the assertion above is not vacuous.
func TestScrubDetectorIsNotBlind(t *testing.T) {
	c := canary.New()
	if !c.In("x" + base64.StdEncoding.EncodeToString([]byte("a"+c.Value(1)))) {
		t.Fatal("canary cannot see a shifted base64 form")
	}
}

// Cutting the output, at the limit or at the capture, must leave no part of
// the value: tried at every limit, so the value starts before, inside and
// after every boundary.
func TestScrubTruncationDoesNotLeakAPrefix(t *testing.T) {
	val := "kc0123456789abcdef-v1-secret"
	pad := strings.Repeat("x", 40)
	text := pad + val + strings.Repeat("y", 300)
	for limit := 1; limit < len(text); limit++ {
		out, _ := scrubOf(t, val, text, limit)
		if strings.Contains(out, val[:6]) || strings.Contains(out, val[len(val)-6:]) {
			t.Fatalf("limit %d: a part of the value survived: %q", limit, out)
		}
	}
	// Positive control: with no cut the value is replaced, not just absent.
	if out, _ := scrubOf(t, val, text, 1<<16); !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("control: %q", out)
	}
}

// Many copies, so that the replacements shrink the text below the limit and
// the half-copy the capture cut stays at the very end unless it is dropped.
func TestScrubDropsTheHalfCopyAtTheEndOfTheCapture(t *testing.T) {
	val := "kc0123456789abcdef-v1-secret"
	text := strings.Repeat(val+"-", 60)
	for limit := 1; limit < len(text); limit++ {
		out, _ := scrubOf(t, val, text, limit)
		if strings.Contains(out, val[:6]) {
			t.Fatalf("limit %d: the start of a copy survived at the end: %q", limit, out[len(out)-40:])
		}
	}
}

// base64(1) wraps its text at 76 columns: the form is broken by newlines.
func TestScrubWithholdsOutputWhenWrappedBase64CarriesTheValue(t *testing.T) {
	val := strings.Repeat("kc0123456789abcdef", 4)
	enc := base64.StdEncoding.EncodeToString([]byte(val))
	var wrapped strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		wrapped.WriteString(enc[i:end] + "\n")
	}
	if !strings.Contains(wrapped.String(), "\n") || strings.Contains(wrapped.String(), enc) {
		t.Fatal("fixture is not wrapped")
	}
	out, _ := scrubOf(t, val, "header\n"+wrapped.String(), 1<<16)
	if out != "[REDACTED]" {
		t.Fatalf("wrapped base64 reached the host output: %q", out)
	}
	if clean, _ := scrubOf(t, val, "a\nb\n", 100); clean != "a\nb\n" {
		t.Fatalf("clean multi-line output changed: %q", clean)
	}
}

func TestScrubKeepsCleanOutputAndReportsSize(t *testing.T) {
	out, truncated := scrubOf(t, "kc0123456789abcdef-v1-secret", "plain output\n", 1<<16)
	if out != "plain output\n" || truncated {
		t.Fatalf("clean output changed: %q truncated=%v", out, truncated)
	}
}

func TestScrubEmptyValueRedactsNothing(t *testing.T) {
	out, _ := scrubOf(t, "", "abc", 100)
	if out != "abc" {
		t.Fatalf("an empty value must not match everywhere: %q", out)
	}
}

// A value with characters that URL escaping changes: both escapes of it must
// go, in text that carries nothing else.
func TestScrubRemovesURLEscapedForms(t *testing.T) {
	val := "p@ss w/rd&x=1"
	for name, form := range map[string]string{"query": url.QueryEscape(val), "path": url.PathEscape(val)} {
		if form == val {
			t.Fatalf("%s: the fixture does not change under escaping", name)
		}
		out, _ := scrubOf(t, val, "q="+form+"\n", 1<<16)
		if out != "q=[REDACTED]\n" {
			t.Errorf("%s: got %q", name, out)
		}
	}
}

// One form of the value can contain another: the raw "35" sits inside its own
// hex "3335". The longer form must be replaced whole, not eaten from inside.
func TestScrubReplacesTheLongerFormWhole(t *testing.T) {
	out, _ := scrubOf(t, "35", "3335", 1<<16)
	if out != "[REDACTED]" {
		t.Fatalf("got %q, want the hex form replaced whole", out)
	}
}

func TestCapWriterKeepsTheLimitAndCountsTheRest(t *testing.T) {
	w := capWriter{limit: 5}
	for _, chunk := range []string{"abc", "defgh", "ij"} {
		if n, err := w.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("write %q: %d %v", chunk, n, err)
		}
	}
	if w.buf.String() != "abcde" || w.total != 10 {
		t.Fatalf("buf=%q total=%d", w.buf.String(), w.total)
	}
}

// The canary is URL-safe, so on it the raw form hides behind the escaped ones
// and the four base64 alphabets look alike. These values do not.
func TestScrubRawFormOfAValueURLEscapingChanges(t *testing.T) {
	val := "p/a+s=s&w dé secret value 0123456789"
	out, _ := scrubOf(t, val, "before "+val+" after\n", 1<<16)
	if out != "before [REDACTED] after\n" {
		t.Fatalf("raw form survived or the output was damaged: %q", out)
	}
}

// pureText is the base64 text of the groups made only of val's own bytes when
// val starts offset bytes into a group.
func pureText(enc *base64.Encoding, val []byte, offset int) string {
	full := append(bytes.Repeat([]byte{'x'}, offset), val...)
	full = append(full, "yy"...)
	text := enc.EncodeToString(full)
	first := (offset + 2) / 3
	last := (offset + len(val)) / 3
	return strings.TrimRight(text[4*first:4*last], "=")
}

func TestScrubEveryBase64AlphabetAndAlignment(t *testing.T) {
	val := append([]byte{0xfb, 0xff, 0xbe, 0xfb, 0xff, 0xbe, 0xfb, 0xff, 0xbe, 0xff, 0xfb}, []byte("tail-0123456789")...)
	encs := map[string]*base64.Encoding{
		"std": base64.StdEncoding, "url": base64.URLEncoding,
		"rawstd": base64.RawStdEncoding, "rawurl": base64.RawURLEncoding,
	}
	for name, enc := range encs {
		for offset := 0; offset <= 2; offset++ {
			pure := pureText(enc, val, offset)
			if len(pure) < 12 {
				t.Fatalf("%s/%d: value too short for the test", name, offset)
			}
			full := append(bytes.Repeat([]byte{'x'}, offset), val...)
			full = append(full, "yy"...)
			out, _ := scrubOf(t, string(val), "before "+enc.EncodeToString(full)+" after\n", 1<<16)
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("%s/%d: nothing scrubbed: %q", name, offset, out)
			}
			for _, part := range []string{pure[:4], pure[len(pure)-4:]} {
				if strings.Contains(out, part) {
					t.Errorf("%s/%d: %q of the value survived in %q", name, offset, part, out)
				}
			}
		}
	}
}

// The groups at either end of a value share characters with the bytes around
// it, so they decode to the value's first and last bytes. Nothing of the
// encoded value may be left standing next to the marker.
func TestScrubTakesTheEdgeGroupsOfBase64(t *testing.T) {
	val := []byte("edge-secret-0123456789")
	for offset := 0; offset <= 2; offset++ {
		// The filler after the value makes whole groups, so what is left of
		// the text beside the marker could only come from the value.
		for tail := (3 - (offset+len(val))%3) % 3; tail <= 2; tail += 3 {
			full := append(bytes.Repeat([]byte{'x'}, offset), val...)
			full = append(full, bytes.Repeat([]byte{'y'}, tail)...)
			text := base64.RawStdEncoding.EncodeToString(full)
			out, _ := scrubOf(t, string(val), text, 1<<16)
			if out != "[REDACTED]" {
				t.Errorf("offset %d tail %d: %q left of %q", offset, tail, out, text)
			}
		}
	}
}
