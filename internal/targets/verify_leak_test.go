//go:build unix

package targets

import (
	"time"

	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

type verifyFixture struct {
	dir    string
	key    fingerprint.Key
	target string   // the canary under verification
	others []string // neighbouring secrets that must never surface
	c      canary.Canary
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	k, err := fingerprint.GenerateKey("k1")
	if err != nil {
		t.Fatal(err)
	}
	c := canary.New()
	return &verifyFixture{dir: t.TempDir(), key: k, target: c.Value(1), others: []string{c.Value(2), c.Value(3)}, c: c}
}

func (f *verifyFixture) fp(t *testing.T, v string) string {
	t.Helper()
	fp, err := fingerprint.Compute(f.key, secret.New([]byte(v)))
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func (f *verifyFixture) write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(f.dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// seen reports whether any secret of the fixture shows in s, in any of the
// canary encodings, including the three base64 shifts the detector is blind to.
func (f *verifyFixture) seen(s string) bool {
	for _, v := range append([]string{f.target}, f.others...) {
		if f.c.In(s) || strings.Contains(s, v) {
			return true
		}
		for _, p := range []string{"", "x", "xx"} {
			enc := base64.StdEncoding.EncodeToString([]byte(p + v))
			if len(enc) > 8 && strings.Contains(s, enc[4:len(enc)-4]) {
				return true
			}
		}
		if strings.Contains(s, hex.EncodeToString([]byte(v))) {
			return true
		}
	}
	return false
}

func (f *verifyFixture) cases(t *testing.T) []struct {
	name string
	spec readSpec
} {
	meshAgents := fmt.Sprintf(`{"mesh_api_url":"https://x.invalid","agents":[{"name":"sage","agent_key":%q},{"name":"bender","agent_key":%q},{"name":"goku","agent_key":%q}]}`,
		f.target, f.others[0], f.others[1])
	mcp := fmt.Sprintf(`{"mcpServers":{"evc-mesh":{"env":{"MESH_AGENT_KEY":%q,"OTHER":%q}}}}`, f.target, f.others[0])
	env := fmt.Sprintf("OTHER=%s\nexport MESH_AGENT_KEY='%s'\nLATER=%s\n", f.others[0], f.target, f.others[1])
	return []struct {
		name string
		spec readSpec
	}{
		{"mesh-agents", readSpec{Format: formatJSON, Path: f.write(t, "mesh-agents.json", meshAgents), Field: "agents[name=sage].agent_key"}},
		{"fiddler", readSpec{Format: formatJSON, Path: f.write(t, "fiddler.json", meshAgents), Field: "agents[name=sage].agent_key"}},
		{"mcp-json", readSpec{Format: formatJSON, Path: f.write(t, ".mcp.json", mcp), Field: "mcpServers.evc-mesh.env.MESH_AGENT_KEY"}},
		{"agent-env", readSpec{Format: formatEnv, Path: f.write(t, "sage.env", env), Field: "MESH_AGENT_KEY"}},
	}
}

// TestVerifyMatchAndMismatchNeverLeak: every outcome, including every error,
// is free of the verified key and of the neighbouring secrets in the file.
func TestVerifyMatchAndMismatchNeverLeak(t *testing.T) {
	f := newVerifyFixture(t)
	if !f.seen("prefix "+f.target) || !f.seen(hex.EncodeToString([]byte(f.target))) {
		t.Fatal("detector is blind; the test proves nothing")
	}
	for _, tc := range f.cases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifySpec(tc.spec, f.fp(t, f.target), f.key)
			if err != nil || got != VerifyMatch {
				t.Fatalf("match: got %q err %v", got, err)
			}
			got, err = verifySpec(tc.spec, f.fp(t, f.others[0]), f.key)
			if err != nil || got != VerifyMismatch {
				t.Fatalf("mismatch: got %q err %v", got, err)
			}
			for _, out := range []string{
				fmt.Sprintf("%v %+v %#v %s", got, got, got, got),
				fmt.Sprintf("%v %+v %#v", tc.spec, tc.spec, tc.spec),
			} {
				if f.seen(out) {
					t.Fatalf("secret surfaced in result formatting: %q", out)
				}
			}
		})
	}
}

// TestVerifyErrorsNeverLeak feeds inputs that fail in every way a hostile or
// broken carrier can and checks the error text.
func TestVerifyErrorsNeverLeak(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	bad := []struct {
		name string
		spec readSpec
		fp   string
	}{
		{"truncated-json", readSpec{formatJSON, f.write(t, "a.json", `{"agents":[{"name":"sage","agent_key":"`+f.target), "agents[name=sage].agent_key"}, good},
		{"not-a-string", readSpec{formatJSON, f.write(t, "b.json", `{"agents":[{"name":"sage","agent_key":{"k":"`+f.target+`"}}]}`), "agents[name=sage].agent_key"}, good},
		{"ambiguous", readSpec{formatJSON, f.write(t, "c.json", `{"agents":[{"name":"sage","agent_key":"`+f.target+`"},{"name":"sage","agent_key":"`+f.others[0]+`"}]}`), "agents[name=sage].agent_key"}, good},
		{"object-selected", readSpec{formatJSON, f.write(t, "d.json", `{"agents":{"k":"`+f.target+`"}}`), "agents"}, good},
		{"bad-selector", readSpec{formatJSON, f.write(t, "e.json", `{"a":"`+f.target+`"}`), "a[["}, good},
		{"bad-fingerprint", readSpec{formatJSON, f.write(t, "f.json", `{"a":"`+f.target+`"}`), "a"}, f.target},
		{"env-dup-form", readSpec{formatEnv, f.write(t, "g.env", "K="+f.target+"\nK=$(echo "+f.others[0]+")\n"), "K"}, good},
		{"env-unterminated", readSpec{formatEnv, f.write(t, "h.env", "K='"+f.target+"\n"), "K"}, good},
		{"unknown-format", readSpec{readFormat("yaml"), f.write(t, "i.yml", "k: "+f.target), "k"}, good},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifySpec(tc.spec, tc.fp, f.key)
			if err == nil {
				t.Fatalf("expected an error, got %q", got)
			}
			if got == VerifyMatch {
				t.Fatal("an error must never come with a match")
			}
			if !errors.Is(err, ErrWrite) && !errors.Is(err, ErrPolicy) {
				t.Fatalf("unclassified error: %v", err)
			}
			for _, s := range []string{err.Error(), fmt.Sprintf("%+v %#v", err, err)} {
				if f.seen(s) {
					t.Fatalf("secret surfaced in error: %q", s)
				}
			}
		})
	}
}

func TestVerifyAbsentAndRefusals(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	cs := f.cases(t)
	if got, err := verifySpec(readSpec{formatJSON, cs[0].spec.Path, "agents[name=nobody].agent_key"}, good, f.key); err != nil || got != VerifyAbsent {
		t.Fatalf("absent element: %q %v", got, err)
	}
	if got, err := verifySpec(readSpec{formatEnv, cs[3].spec.Path, "NOPE"}, good, f.key); err != nil || got != VerifyAbsent {
		t.Fatalf("absent variable: %q %v", got, err)
	}
	if got, err := verifySpec(readSpec{formatJSON, filepath.Join(f.dir, "missing.json"), "a"}, good, f.key); err != nil || got != VerifyAbsent {
		t.Fatalf("absent file: %q %v", got, err)
	}
	link := filepath.Join(f.dir, "link.json")
	if err := os.Symlink(cs[0].spec.Path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySpec(readSpec{formatJSON, link, "agents[name=sage].agent_key"}, good, f.key); !errors.Is(err, ErrPolicy) {
		t.Fatalf("symlink must be refused by policy, got %v", err)
	}
	if _, err := verifySpec(readSpec{formatJSON, "relative.json", "a"}, good, f.key); !errors.Is(err, ErrPolicy) {
		t.Fatalf("relative path must be refused, got %v", err)
	}
	if got, err := verifySpec(readSpec{formatEnv, f.write(t, "empty.env", "MESH_AGENT_KEY=\n"), "MESH_AGENT_KEY"}, good, f.key); err != nil || got != VerifyMismatch {
		t.Fatalf("empty value must be a mismatch: %q %v", got, err)
	}
}

// TestVerifyWipesWhatItRead: the file buffer and the extracted copy of the
// value are zeroed before Verify returns (not left for the GC).
func TestVerifyWipesWhatItRead(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	for _, tc := range f.cases(t) {
		t.Run(tc.name, func(t *testing.T) {
			var wholeFile, exactValue bool
			file, err := os.ReadFile(tc.spec.Path)
			if err != nil {
				t.Fatal(err)
			}
			orig := wipe
			defer func() { wipe = orig }()
			wipe = func(b []byte) {
				switch {
				case string(b) == f.target:
					exactValue = true
				case string(b) == string(file):
					wholeFile = true
				}
				orig(b)
			}
			if got, err := verifySpec(tc.spec, good, f.key); err != nil || got != VerifyMatch {
				t.Fatalf("got %q %v", got, err)
			}
			if !exactValue {
				t.Fatal("the extracted copy of the value was not wiped")
			}
			if !wholeFile {
				t.Fatal("the file buffer was not wiped")
			}
		})
	}
}

func TestVerifyRefusesNonRegularAndReadsLastAssignment(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	if _, err := verifySpec(readSpec{formatEnv, f.dir, "K"}, good, f.key); !errors.Is(err, ErrPolicy) {
		t.Fatalf("a directory must be refused by policy, got %v", err)
	}
	// Last assignment wins; a variable that only starts with the name does not count.
	p := f.write(t, "last.env", "K="+f.others[0]+"\nK_OLD="+f.others[1]+"\nK="+f.target+" # trailing\nK_OTHER="+f.others[1]+"\n")
	if got, err := verifySpec(readSpec{formatEnv, p, "K"}, good, f.key); err != nil || got != VerifyMatch {
		t.Fatalf("last assignment: %q %v", got, err)
	}
	q := f.write(t, "dq.env", "K=\""+f.target+"\"\n")
	if got, err := verifySpec(readSpec{formatEnv, q, "K"}, good, f.key); err != nil || got != VerifyMatch {
		t.Fatalf("double quoted: %q %v", got, err)
	}
}

func TestVerifyEnvSyntaxTable(t *testing.T) {
	f := newVerifyFixture(t)
	v := f.target
	for name, tc := range map[string]struct {
		line string
		want VerifyResult
	}{
		"hash-in-word-is-value": {"K=" + v + "#x\n", VerifyMismatch},
		"comment-after-blank":   {"K=" + v + " # note\n", VerifyMatch},
		"export-space":          {"export K=" + v + "\n", VerifyMatch},
		"export-tab":            {"export\tK=" + v + "\n", VerifyMatch},
		"export-prefixed-name":  {"exportK=" + v + "\n", VerifyAbsent},
		"crlf":                  {"K=" + v + "\r\n", VerifyMatch},
		"no-final-newline":      {"K=" + v, VerifyMatch},
		"leading-blanks":        {"  K=" + v + "\n", VerifyMatch},
		"commented-out":         {"#K=" + v + "\n", VerifyAbsent},
		"space-around-equals":   {"K = " + v + "\n", VerifyAbsent},
	} {
		got, err := verifySpec(readSpec{formatEnv, f.write(t, "t.env", tc.line), "K"}, f.fp(t, v), f.key)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q %v, want %q", name, got, err, tc.want)
		}
	}
	// Every form that needs a shell to be read is refused, one character each.
	for name, line := range map[string]string{
		"dollar":       "K=a$b\n",
		"backtick":     "K=a`b`\n",
		"backslash":    "K=a\\b\n",
		"lparen":       "K=a(b\n",
		"rparen":       "K=a)b\n",
		"semicolon":    "K=a;b\n",
		"ampersand":    "K=a&b\n",
		"pipe":         "K=a|b\n",
		"lt":           "K=a<b\n",
		"gt":           "K=a>b\n",
		"dq-dollar":    "K=\"a$b\"\n",
		"dq-backtick":  "K=\"a`b`\"\n",
		"dq-backslash": "K=\"a\\b\"\n",
	} {
		_, err := verifySpec(readSpec{formatEnv, f.write(t, "x.env", line), "K"}, f.fp(t, v), f.key)
		if !errors.Is(err, ErrWrite) {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
	for name, field := range map[string]string{"empty": "", "blank": "A B", "equals": "A=B"} {
		if _, err := verifySpec(readSpec{formatEnv, f.write(t, "n.env", "K=1\n"), field}, f.fp(t, v), f.key); !errors.Is(err, ErrWrite) {
			t.Errorf("variable name %s: want a refusal, got %v", name, err)
		}
	}
}

func TestVerifySelectorTableAndLimits(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	doc := f.write(t, "s.json", fmt.Sprintf(`{"a":{"b":%q},"arr":[1,{"x":5},{"name":"n","k":%q}],"s":"plain"}`, f.target, f.target))
	for _, field := range []string{"", "a[", "a[x]", "a[=v]", "a[k=]", "arr[=n].k", "arr[name=].k", "a[k=[v]]", "[k=v].z", "a..b", ".a", "arr[name=n"} {
		if _, err := verifySpec(readSpec{formatJSON, doc, field}, good, f.key); !errors.Is(err, ErrWrite) {
			t.Errorf("selector %q: want a refusal, got %v", field, err)
		}
	}
	for name, field := range map[string]string{"through-string": "s.z", "pick-on-object": "a[k=v].b"} {
		if _, err := verifySpec(readSpec{formatJSON, doc, field}, good, f.key); !errors.Is(err, ErrWrite) {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
	if got, err := verifySpec(readSpec{formatJSON, doc, "arr[name=n].k"}, good, f.key); err != nil || got != VerifyMatch {
		t.Errorf("element past a non-object sibling: %q %v", got, err)
	}
	if got, err := verifySpec(readSpec{formatJSON, doc, "a.nothing"}, good, f.key); err != nil || got != VerifyAbsent {
		t.Errorf("missing key: %q %v", got, err)
	}
	big := f.write(t, "big.env", "K=1\n"+strings.Repeat("#", maxTargetSize))
	if _, err := verifySpec(readSpec{formatEnv, big, "K"}, good, f.key); !errors.Is(err, ErrWrite) {
		t.Errorf("oversized carrier: want a refusal, got %v", err)
	}
}

func TestVerifyFIFODoesNotHang(t *testing.T) {
	f := newVerifyFixture(t)
	p := filepath.Join(f.dir, "fifo")
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo unavailable")
	}
	done := make(chan error, 1)
	go func() {
		_, err := verifySpec(readSpec{formatEnv, p, "K"}, f.fp(t, f.target), f.key)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrPolicy) {
			t.Fatalf("a FIFO must be refused by policy, got %v", err)
		}
	case <-time.After(5 * time.Second):
		// Unblock the stuck open so the goroutine ends, then fail.
		if fd, err := unix.Open(p, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			_ = unix.Close(fd)
		}
		t.Fatal("Verify hangs on a FIFO")
	}
}

// The error branches that sit next to a neighbour's value, fed with
// canaries, and a key that cannot compute a fingerprint.
func TestVerifyNeighbourBranchesNeverLeak(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	doc := f.write(t, "n.json", fmt.Sprintf(`{"s":%q,"o":{"k":%q},"arr":%q,"ctl":"%s\u0001"}`, f.others[0], f.others[1], f.others[0], f.others[1]))
	for name, field := range map[string]string{
		"through-string":  "s.z",
		"pick-on-string":  "s[k=v].z",
		"pick-on-object":  "o[k=v].z",
		"object-as-field": "o",
	} {
		_, err := verifySpec(readSpec{formatJSON, doc, field}, good, f.key)
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if f.seen(err.Error()) {
			t.Fatalf("%s: neighbour surfaced in error %q", name, err)
		}
	}
	bad := f.write(t, "bad.json", `{"x":"`+f.others[0]+"\x01\"}")
	if _, err := verifySpec(readSpec{formatJSON, bad, "x"}, good, f.key); err == nil || strings.Contains(err.Error(), "byte") {
		t.Fatalf("a syntax error must not name a byte offset, got %v", err)
	}
	var zero fingerprint.Key
	_, err := verifySpec(readSpec{formatJSON, doc, "ctl"}, good, zero)
	if err == nil || f.seen(err.Error()) {
		t.Fatalf("zero key must fail without the value: %v", err)
	}
}

// TestVerifyWipesTheSecretCopy: secret.New copies the extracted bytes; that
// second copy is zeroed once the fingerprint is computed.
func TestVerifyWipesTheSecretCopy(t *testing.T) {
	f := newVerifyFixture(t)
	good := f.fp(t, f.target)
	for _, tc := range f.cases(t) {
		t.Run(tc.name, func(t *testing.T) {
			orig := computeFingerprint
			t.Cleanup(func() { computeFingerprint = orig })
			var seen secret.Value
			var calls int
			computeFingerprint = func(k fingerprint.Key, v secret.Value) (string, error) {
				calls++
				seen = v
				return orig(k, v)
			}
			if got, err := verifySpec(tc.spec, good, f.key); err != nil || got != VerifyMatch {
				t.Fatalf("got %q %v", got, err)
			}
			if calls != 1 {
				t.Fatalf("computeFingerprint fired %d times, want 1", calls)
			}
			nonzero := false
			secret.Expose(seen, func(b []byte) {
				if len(b) == 0 {
					t.Fatal("the copy was empty: the check proves nothing")
				}
				for _, c := range b {
					nonzero = nonzero || c != 0
				}
			})
			if nonzero {
				t.Fatal("the secret.Value copy was not wiped")
			}
		})
	}
}
