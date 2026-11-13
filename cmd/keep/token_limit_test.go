package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// endlessReader never reaches EOF and counts the bytes handed out, so a
// reader that is drained past the limit shows up as a count, not a hang.
type endlessReader struct {
	b    byte
	read int
}

func (e *endlessReader) Read(p []byte) (int, error) {
	// Safety stop: an unbounded consumer sees EOF after 1 MiB and fails the
	// assertions below instead of hanging the test binary.
	if e.read >= 1<<20 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = e.b
	}
	e.read += len(p)
	return len(p), nil
}

func TestTokenInputByteLimit(t *testing.T) {
	const canaryByte = 'Q'
	c := canary.New()
	// Exactly n raw bytes that start with the synthetic canary, so a leak of
	// the head of the input is caught in every encoding the canary covers.
	mk := func(n int) string { return c.Value(0) + strings.Repeat(string(rune(canaryByte)), n-len(c.Value(0))) }
	noLeak := func(t *testing.T, outputs ...string) {
		t.Helper()
		for _, o := range outputs {
			if c.In(o) {
				t.Fatalf("canary leaked into output")
			}
		}
	}

	t.Run("login stdin at limit is stored", func(t *testing.T) {
		dir := t.TempDir()
		tf := filepath.Join(dir, "keep", "token")
		var stderr bytes.Buffer
		code := runLoginSubcommand([]string{"--token-file", tf}, strings.NewReader(mk(maxTokenInputBytes)), &stderr, func(string) string { return "" })
		if code != 0 {
			t.Fatalf("code = %d, want 0", code)
		}
		st, err := os.Stat(tf)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("token file missing or wrong mode: %v", err)
		}
		noLeak(t, stderr.String())
		// Round trip: whatever login stored must be readable by resolveToken,
		// at the boundary too, and the file itself stays within the limit.
		tok, err := resolveToken(func(string) string { return "" }, tf)
		if err != nil || tok != mk(maxTokenInputBytes) {
			t.Fatalf("round trip at limit failed: err=%v len=%d", err, len(tok))
		}
		if st.Size() > maxTokenInputBytes {
			t.Fatalf("stored file is %d bytes, over the limit", st.Size())
		}
	})

	t.Run("login round trip just under the limit keeps newline", func(t *testing.T) {
		tf := filepath.Join(t.TempDir(), "token")
		var stderr bytes.Buffer
		if code := runLoginSubcommand([]string{"--token-file", tf}, strings.NewReader(mk(maxTokenInputBytes-1)), &stderr, func(string) string { return "" }); code != 0 {
			t.Fatalf("code = %d", code)
		}
		tok, err := resolveToken(func(string) string { return "" }, tf)
		if err != nil || tok != mk(maxTokenInputBytes-1) {
			t.Fatalf("round trip failed: err=%v", err)
		}
		raw, _ := os.ReadFile(tf) //nolint:gosec // test reads its own temp file
		if len(raw) != maxTokenInputBytes {
			t.Fatalf("stored size = %d, want %d", len(raw), maxTokenInputBytes)
		}
	})

	t.Run("login stdin over limit is rejected and old file kept", func(t *testing.T) {
		for name, input := range map[string]string{
			"canary":     mk(maxTokenInputBytes + 1),
			"whitespace": "x" + strings.Repeat(" ", maxTokenInputBytes),
			"huge":       mk(1 << 20),
		} {
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				tf := filepath.Join(dir, "token")
				old := []byte("keep_a_old_token\n")
				if err := os.WriteFile(tf, old, 0o600); err != nil {
					t.Fatal(err)
				}
				var stderr bytes.Buffer
				code := runLoginSubcommand([]string{"--token-file", tf}, strings.NewReader(input), &stderr, func(string) string { return "" })
				if code == 0 {
					t.Fatalf("code = 0, want nonzero")
				}
				got, _ := os.ReadFile(tf) //nolint:gosec // test reads its own temp file
				if !bytes.Equal(got, old) {
					t.Fatalf("existing token file changed")
				}
				ents, _ := os.ReadDir(dir)
				if len(ents) != 1 {
					t.Fatalf("stray files left in token dir: %d entries", len(ents))
				}
				noLeak(t, stderr.String())
				if strings.Contains(stderr.String(), dir) {
					t.Fatalf("path leaked into error")
				}
			})
		}
	})

	t.Run("login stdin over limit with no prior file creates none", func(t *testing.T) {
		dir := t.TempDir()
		tf := filepath.Join(dir, "token")
		var stderr bytes.Buffer
		if code := runLoginSubcommand([]string{"--token-file", tf}, strings.NewReader(mk(maxTokenInputBytes+1)), &stderr, func(string) string { return "" }); code == 0 {
			t.Fatalf("code = 0")
		}
		if _, err := os.Stat(tf); !os.IsNotExist(err) {
			t.Fatalf("token file created: %v", err)
		}
	})

	t.Run("endless reader is not drained past limit+1", func(t *testing.T) {
		er := &endlessReader{b: canaryByte}
		_, err := readTokenBounded(er)
		if !errors.Is(err, errTokenTooLarge) {
			t.Fatalf("err = %v, want errTokenTooLarge", err)
		}
		// io.LimitReader caps each Read at the remaining budget, so the
		// total handed out must be exactly limit+1 at most — no slack.
		if er.read > maxTokenInputBytes+1 {
			t.Fatalf("reader drained: %d bytes", er.read)
		}
		er2 := &endlessReader{b: ' '}
		var stderr bytes.Buffer
		if code := runLoginSubcommand([]string{"--token-file", filepath.Join(t.TempDir(), "t")}, er2, &stderr, func(string) string { return "" }); code == 0 {
			t.Fatalf("code = 0")
		}
		if er2.read > maxTokenInputBytes+1 {
			t.Fatalf("login drained reader: %d bytes", er2.read)
		}
	})

	t.Run("resolveToken file", func(t *testing.T) {
		dir := t.TempDir()
		ok := filepath.Join(dir, "ok")
		body := mk(maxTokenInputBytes-1) + "\n"
		if err := os.WriteFile(ok, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		tok, err := resolveToken(func(string) string { return "" }, ok)
		if err != nil || tok != mk(maxTokenInputBytes-1) {
			t.Fatalf("at-limit file: err=%v len=%d", err, len(tok))
		}
		for name, content := range map[string]string{
			"canary":     mk(maxTokenInputBytes + 1),
			"whitespace": "x" + strings.Repeat(" ", maxTokenInputBytes),
		} {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			tok, err := resolveToken(func(string) string { return "" }, p)
			if err == nil || tok != "" {
				t.Fatalf("%s: oversized file accepted (err=%v)", name, err)
			}
			if !strings.Contains(err.Error(), "larger than 4096") {
				t.Fatalf("%s: oversize not reported as such: %v", name, err)
			}
			if strings.Contains(err.Error(), p) {
				t.Fatalf("path in error")
			}
			noLeak(t, err.Error())
			var stderr bytes.Buffer
			reportErr(&stderr, err)
			noLeak(t, stderr.String())
		}
	})
}

var _ io.Reader = (*endlessReader)(nil)
