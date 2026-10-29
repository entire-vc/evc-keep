//go:build unix

//nolint:gosec,errcheck // attack fixtures live in a temp dir, setup errors are irrelevant to the assertion, and the fuzz seed must be reproducible
package targets_test

import (
	"context"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Differential attack on the env-file writer: for random hostile existing
// files and random hostile values, either the writer refuses, or every shell
// that sources the result must (1) run no command, (2) see the new value for
// the field byte for byte, (3) see every other variable exactly as it saw it
// in the file before the write. Shells are the consumer named in the MR.
// Fake values only; commands are confined to `touch PWNED` in a temp dir.

var fuzzTokens = []string{
	"A", "B", "NAME", "FOO", "x", "1", "=", "==", "'", "\"", "$", "$(touch PWNED)", "`touch PWNED`", "${A}", "${A:-", "}",
	"(", ")", "\\", "\\\n", "#", ";", "&", "&&", "|", "<", ">", " ", "\t", "  ", "\n", "\n", "\n", "export ", "export", "NAME=", "A=",
	"FOO=", "'x'", "\"y\"", "touch PWNED", "$'a'", "$\"b\"", "~", "*", "?", "[", "]", "{", "!", "\x0b", "\x0c", "\r", "\xc3\xa9", "\xff",
	"local ", "readonly ", "unset ", "eval ", ". ", "IFS=", "PATH=", "PS1=", "PS4=", "ENV=", "BASH_ENV=", "SHELLOPTS=", "LINENO=",
	"RANDOM=", "SECONDS=", "_=", "PWD=", "OLDPWD=", "HOME=", "OPTIND=", "+=", "[0]=", "A[0]=", "A[$(touch PWNED)]=", "((", "))", "$((",
	"<<EOF\n", "EOF\n", "%", "@", ",", ":", "/", "-", "+",
}

var fuzzValueAlpha = []string{
	"a", "Z", "0", "_", "-", "/", ".", ":", "@", "%", "+", ",", " ", "\t", "'", "\"", "$", "`", "\\", "#", ";", "&", "|", "<", ">", "(", ")",
	"{", "}", "[", "]", "*", "?", "!", "~", "=", "\x0b", "\x0c", "\x01", "\x7f", "\xc3\xa9", "\xff", "$(touch PWNED)", "`touch PWNED`", "${A}", "$'", "\\'",
}

// fuzzEscapeAlpha is a narrow slice of fuzzValueAlpha, weighted toward
// backslash and apostrophe next to bare characters. shellUnquote treats a
// bare `\'` as an escaped quote — the same convention envEscQuote uses
// inside a quoted run — so a value shaped like `\'-_::` round-trips through
// this package's own readback whether or not shellQuote actually quoted it,
// and only a real shell's own (different) escaping rule exposes the gap. A
// value drawn from the full 46-symbol fuzzValueAlpha only stumbles onto this
// shape by chance (empirically needing thousands of iterations at the
// default seed); drawing a third of iterations from this narrower alphabet
// makes the shape common enough to show up well within the default
// iteration budget regardless of seed.
var fuzzEscapeAlpha = []string{
	"\\", "'", "\\'", "'\\''", "a", "Z", "0", "-", "_", ":", ".", "/",
}

func fuzzGen(r *rand.Rand, alpha []string, maxTok int) string {
	n := r.Intn(maxTok) + 1
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(alpha[r.Intn(len(alpha))])
	}
	return b.String()
}

var shellCmds = map[string][]string{
	"bash": {"bash", "--noprofile", "--norc"},
	"dash": {"dash"},
	"zsh":  {"zsh", "-f"},
	"ksh":  {"ksh"},
	"mksh": {"mksh"},
}

// sourceIt sources file in a fresh empty environment and returns the
// exported-variable dump without the given field, that field's value, and
// whether a command ran and whether the shell complained.
func sourceIt(t *testing.T, sh []string, dir, file, field string) (dump, val string, pwned, noisy bool) {
	t.Helper()
	// The hostile file is sourced from an empty scratch cwd: a neighbour such as
	// A=x>* must not be able to truncate the file under test.
	run := filepath.Join(filepath.Dir(dir), "run-"+filepath.Base(dir))
	os.RemoveAll(run)
	os.MkdirAll(run, 0o755)
	defer os.RemoveAll(run)
	script := `set -a; . "$1" 2>"$2"; set +a; export -p >"$4"; eval "v=\${$5-<unset>}"; printf '%s' "$v" >"$3"`
	args := append(append([]string{}, sh[1:]...), "-c", script, "sh", file, filepath.Join(run, "err"), filepath.Join(run, "val"), filepath.Join(run, "dump"), field)
	// A hostile line is the whole point of this fuzz: a value or existing
	// entry that makes the shell hang (e.g. an unterminated here-doc reading
	// from its own stdin, or one that blocks on a read) must fail this
	// iteration's assertions, not eat the rest of the job's time budget.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, sh[0], args...)
	c.Dir = run
	c.Env = []string{"HOME=" + dir, "PATH=/usr/bin:/bin", "LC_ALL=C"}
	c.Stdin = nil
	_ = c.Run()
	_, statErr := os.Stat(filepath.Join(run, "PWNED"))
	e, _ := os.ReadFile(filepath.Join(run, "err"))
	v, _ := os.ReadFile(filepath.Join(run, "val"))
	d, _ := os.ReadFile(filepath.Join(run, "dump"))
	// drop the field's own line(s) and per-run noise from the dump
	var keep []string
	for _, l := range strings.Split(string(d), "\n") {
		if strings.Contains(l, field+"=") && strings.HasSuffix(strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(l, "export "), "declare -x "), "=", 2)[0], field) {
			continue
		}
		if strings.Contains(l, "OLDPWD") || strings.Contains(l, " PWD=") || strings.Contains(l, "SHLVL") || strings.Contains(l, "_=") {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n"), string(v), statErr == nil, len(e) > 0
}

func TestTargetsAttack_EnvFileDifferentialShells(t *testing.T) {
	iters := 150
	if s := os.Getenv("KEEP_ATTACK_FUZZ_ITERS"); s != "" {
		iters, _ = strconv.Atoi(s)
	}
	seed := int64(20250925)
	if s := os.Getenv("KEEP_ATTACK_FUZZ_SEED"); s != "" {
		seed, _ = strconv.ParseInt(s, 10, 64)
	}
	r := rand.New(rand.NewSource(seed))
	var shells []string
	for name, c := range shellCmds {
		if _, err := exec.LookPath(c[0]); err == nil {
			shells = append(shells, name)
		}
	}
	if len(shells) == 0 {
		// In CI (the GitLab-set CI=true, not a build tag) this must never
		// pass as a silent SKIP: check-no-silent-skip.sh only greps for the
		// database's own skip message, so an image missing every shell would
		// otherwise report a plain "ok" for a test that ran zero iterations.
		if os.Getenv("CI") != "" {
			t.Fatal("no shell available in CI — the test job's before_script must install bash, dash, zsh, ksh or mksh")
		}
		t.Skip("no shell available")
	}
	wrote, refused := 0, 0
	bad := 0
	nameRe := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	for i := 0; i < iters && bad < 5; i++ {
		d := dir(t)
		p := filepath.Join(d, "svc.env")
		field := []string{"NAME", "FOO"}[r.Intn(2)]
		if !nameRe.MatchString(field) {
			t.Fatal("bad field")
		}
		var existing string
		if r.Intn(4) != 0 {
			// structured: several lines, some plausible some hostile
			nl := r.Intn(4)
			var lines []string
			for j := 0; j < nl; j++ {
				switch r.Intn(3) {
				case 0:
					lines = append(lines, []string{"A", "B", "FOO", "NAME"}[r.Intn(4)]+"="+fuzzGen(r, fuzzValueAlpha, 6))
				case 1:
					lines = append(lines, fuzzGen(r, fuzzTokens, 6))
				default:
					lines = append(lines, "A=1")
				}
			}
			existing = strings.Join(lines, "\n")
			if r.Intn(2) == 0 {
				existing += "\n"
			}
		}
		alpha := fuzzValueAlpha
		if i%3 == 2 {
			alpha = fuzzEscapeAlpha
		}
		val := fuzzGen(r, alpha, 8)
		if strings.ContainsAny(val, "\x00\r\n") {
			continue
		}
		if existing != "" {
			os.WriteFile(p, []byte(existing), 0o600)
		}
		before := map[string][3]string{}
		beforePwn := map[string]bool{}
		for _, sh := range shells {
			if existing == "" {
				continue
			}
			dump, _, pw, noisy := sourceIt(t, shellCmds[sh], d, p, field)
			before[sh] = [3]string{dump, "", strconv.FormatBool(noisy)}
			beforePwn[sh] = pw
		}
		_, err := targets.Write(tgt(runnerproto.TargetEnvFile, p, field), secret.New([]byte(val)), nil, nil, fpKey(t))
		if err != nil {
			refused++
			continue
		}
		wrote++
		after, _ := os.ReadFile(p)
		for _, sh := range shells {
			dump, got, pw, noisy := sourceIt(t, shellCmds[sh], d, p, field)
			// The file was written by the package: it must not run anything the original did not.
			if pw && !beforePwn[sh] {
				bad++
				t.Errorf("[%s] iter %d: command executed after write\nexisting=%q value=%q\nfile=%q", sh, i, existing, val, after)
				continue
			}
			if got != val {
				bad++
				t.Errorf("[%s] iter %d: consumer sees %q, want %q\nexisting=%q\nfile=%q", sh, i, got, val, existing, after)
				continue
			}
			if b, ok := before[sh]; ok && existing != "" {
				if b[0] != dump {
					bad++
					t.Errorf("[%s] iter %d: neighbour variables changed by the write\nexisting=%q value=%q\nfile=%q\nbefore-dump:\n%s\nafter-dump:\n%s", sh, i, existing, val, after, b[0], dump)
					continue
				}
				if b[2] == "false" && noisy {
					bad++
					t.Errorf("[%s] iter %d: shell complained after the write, not before\nexisting=%q value=%q\nfile=%q", sh, i, existing, val, after)
				}
			} else if noisy {
				bad++
				t.Errorf("[%s] iter %d: shell complained on a file the package wrote from scratch\nvalue=%q file=%q", sh, i, val, after)
			}
		}
	}
	t.Logf("shells=%v iters=%d wrote=%d refused=%d bad=%d seed=%d", shells, iters, wrote, refused, bad, seed)
	if wrote < iters/20 {
		t.Fatalf("positive control failed: only %d writes accepted — the fuzz never reached the shell", wrote)
	}
}
