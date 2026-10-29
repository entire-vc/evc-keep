//go:build unix

package targets

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// hermes-config is a NAME=value line in $HERMES_HOME/.env: same file mechanism
// as env-file, byte for byte on the neighboring lines.
func TestHermesConfigWritesEnvLine(t *testing.T) {
	path := filepath.Join(realDir(t), ".env")
	before := "# hermes\nTELEGRAM_BOT_TOKEN=aaa\nEXAMPLE_API_KEY=old\nOTHER='x y'\n"
	mustWriteFile(t, path, []byte(before), 0o600)

	uids, gids := noAgents()
	fp, err := Write(target(runnerproto.TargetHermesConfig, path, "EXAMPLE_API_KEY"), newValue("new-value"), uids, gids, testFPKey(t))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !fingerprint.Valid(fp) {
		t.Fatalf("fingerprint %q is not valid kfp1", fp)
	}
	want := "# hermes\nTELEGRAM_BOT_TOKEN=aaa\nEXAMPLE_API_KEY=new-value\nOTHER='x y'\n"
	if got := string(mustReadFile(t, path)); got != want {
		t.Fatalf("got %s, want %s", show([]byte(got)), show([]byte(want)))
	}
}

func TestHermesConfigAppendsAndCreates(t *testing.T) {
	uids, gids := noAgents()
	fresh := filepath.Join(realDir(t), ".env")
	if _, err := Write(target(runnerproto.TargetHermesConfig, fresh, "EXAMPLE_API_KEY"), newValue("v1"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := string(mustReadFile(t, fresh)); got != "EXAMPLE_API_KEY=v1\n" {
		t.Fatalf("created %s", show([]byte(got)))
	}
	if _, err := Write(target(runnerproto.TargetHermesConfig, fresh, "OTHER"), newValue("v2"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if got := string(mustReadFile(t, fresh)); got != "EXAMPLE_API_KEY=v1\nOTHER=v2\n" {
		t.Fatalf("appended %s", show([]byte(got)))
	}
}

// The old shape (a dotted key path into a JSON document) is not accepted: the
// file stays as it was and nothing is created.
func TestHermesConfigDottedPathInvalid(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, ".env")
	mustWriteFile(t, path, []byte("A=1\n"), 0o600)
	uids, gids := noAgents()
	for _, field := range []string{"mcp_servers.x.env.K", "secrets.API_KEY", "a..b"} {
		_, err := Write(target(runnerproto.TargetHermesConfig, path, field), newValue("v"), uids, gids, testFPKey(t))
		wantErr(t, err, ErrPolicy, "dotted field "+field)
		if got := string(mustReadFile(t, path)); got != "A=1\n" {
			t.Fatalf("file changed despite the refusal: %s", show([]byte(got)))
		}
	}
}

// The reader of this file is Hermes's own loader, which rewrites it before
// python-dotenv parses it and strips non-ASCII from credentials afterwards; a
// value the loader would drop, decode, interpolate, split or echo is refused.
// The refusal is checked in full: file untouched, error without the value, and
// one message for every class so the text says nothing about which one it was.
func TestHermesConfigRefusesValuesTheLoaderMisreads(t *testing.T) {
	var firstMsg string
	for name, v := range map[string]string{
		"single quote":       "it's",
		"only quote":         "'",
		"trailing backslash": `abc\`,
		"double backslash":   `a\\b`,
		"backslash quote":    `a\'b`,
		"lone backslash":     `a\b`,
		"interpolation":      "x${HOME}y",
		"double quote":       `dq "x"`,
		"leading dquote":     `"abc`,
		"trailing dquote":    `abc"`,
		"only dquote":        `"`,
		"interior dquote":    `a"b`,
		"lf":                 "a\nb",
		"cr":                 "a\rb",
		"nul":                "a\x00b",
		"tab":                "a\tb",
		"del":                "a\x7fb",
		"non-ascii":          "synth-é-tail",
		"invalid utf-8":      "ab\xffcd",
		"planted variables":  "xOPENAI_BASE_URL=https://evil.invalid/v1TERMINAL_ENV=local",
		"one variable name":  "OPENAI_API_KEY=x",
		"name run":           "abc_DEF_GHI=x",
		"name run at end":    "xxxTELEGRAM_BOT_TOKEN=",
		"shortest known":     "FAL_KEY=x",
		"six name chars":     "ABCDEF=x",
		"unit separator":     "a\x1fb",
		"digits in the run":  "ABC123=x",
		"digit nine edge":    "ABCDE9=x",
		"digit zero edge":    "ABCDE0=x",
		"letter z edge":      "ABCDEZ=x",
		"letter a edge":      "AAAAAA=x",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(realDir(t), ".env")
			mustWriteFile(t, path, []byte("A=1\n"), 0o600)
			uids, gids := noAgents()
			_, err := Write(target(runnerproto.TargetHermesConfig, path, "X"), newValue(v), uids, gids, testFPKey(t))
			wantErr(t, err, ErrPolicy, "value the loader misreads")
			if strings.Contains(err.Error(), v) {
				t.Errorf("error carries the value: %v", err)
			}
			if firstMsg == "" {
				firstMsg = err.Error()
			} else if err.Error() != firstMsg {
				t.Errorf("refusal text differs between classes: %q vs %q", err.Error(), firstMsg)
			}
			if got := string(mustReadFile(t, path)); got != "A=1\n" {
				t.Fatalf("file changed despite the refusal: %s", show([]byte(got)))
			}
		})
	}
}

// Values that only look close to a refused one are written: an equals sign in
// a URL query or base64 padding, a short name before it, a lone dollar sign.
func TestHermesConfigTakesValuesNextToTheRefusedClasses(t *testing.T) {
	uids, gids := noAgents()
	for _, v := range []string{"a=b", "https://h/p?key=Value&x=1", "abc123/+xyzAA==", "shortAB=", "ABCDE=x", "ABCDEFGH-x", "1234567 x", "ABC d DEF", "ABCDE_x=", "abcABCDE=x", "lower_case_name_x=1", "$", "$HOME", "{}", "a b", "x~y", "a#b", "# c", "semi; colon", "`tick`", " lead", "trail "} {
		path := filepath.Join(realDir(t), ".env")
		if _, err := Write(target(runnerproto.TargetHermesConfig, path, "K"), newValue(v), uids, gids, testFPKey(t)); err != nil {
			t.Errorf("refused %q: %v", v, err)
		}
	}
}

// What is refused for hermes-config is still fine for env-file, whose
// consumers are shells: the guard must not spread to the other kind.
func TestEnvFileStillTakesQuoteBackslashInterpolation(t *testing.T) {
	uids, gids := noAgents()
	for _, v := range []string{"it's", `a\\b`, "x${HOME}y"} {
		path := filepath.Join(realDir(t), "app.env")
		if _, err := Write(target(runnerproto.TargetEnvFile, path, "X"), newValue(v), uids, gids, testFPKey(t)); err != nil {
			t.Errorf("env-file refused %q: %v", v, err)
		}
	}
}

// hermesCmd runs the Hermes interpreter with a minimal environment: the
// loader scrubs credential variables and reports on them, and a developer or CI
// environment may hold real ones that third-party code has no business seeing.
func hermesCmd(py, home string, args ...string) *exec.Cmd {
	cmd := exec.Command(py, args...) //nolint:gosec // G204: the interpreter is the test's explicit input
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "HERMES_HOME=" + home}
	return cmd
}

// hermesPython is the interpreter of the Hermes venv, which also holds the
// Hermes package: the test then reads the file with Hermes's own loader, the
// one that runs in production. Without KEEP_HERMES_PYTHON it skips; run it with
// the variable set before changing the hermes-config rules.
func hermesPython(t *testing.T) string {
	t.Helper()
	py := os.Getenv("KEEP_HERMES_PYTHON")
	if py == "" {
		t.Skip("KEEP_HERMES_PYTHON not set: no Hermes loader to read the file with")
	}
	return py
}

const hermesLoad = `import os, sys
from hermes_cli.env_loader import load_hermes_dotenv
load_hermes_dotenv(hermes_home=sys.argv[1], project_env=os.path.join(sys.argv[1], "none.env"))
v = os.environ.get(sys.argv[2])
sys.stdout.write("<missing>" if v is None else "=" + v)`

// hermesLoadEnv is Hermes's second reader of the file, config.load_env, which
// /reload and the docker sandbox setup use: it strips quote marks from both
// ends of a value where load_hermes_dotenv does not.
const hermesLoadEnv = `import sys
from hermes_cli.config import load_env
v = load_env().get(sys.argv[1])
sys.stdout.write("<missing>" if v is None else "=" + v)`

// Values written as they are must survive both of Hermes's readers: same
// value, file not rewritten, neighbors intact, nothing on stderr.
func TestHermesConfigReadableByHermesLoader(t *testing.T) {
	py := hermesPython(t)
	values := []string{
		"plain", "abc-DEF_123/+=:.,@%", "with space", "hash # inside", "dollar $HOME bare",
		"semi; colon", "`tick`", "$", "{}", "a=b", "https://h/p?key=Value&x=1", "abc123/+xyzAA==", "x~y",
	}
	uids, gids := noAgents()
	dir := realDir(t)
	path := filepath.Join(dir, ".env")
	mustWriteFile(t, path, []byte("FIRST=1\nLAST=2\n"), 0o600)
	key := testFPKey(t)
	for _, v := range values {
		fp, err := Write(target(runnerproto.TargetHermesConfig, path, "EXAMPLE_API_KEY"), newValue(v), uids, gids, key)
		if err != nil {
			t.Fatalf("Write %q: %v", v, err)
		}
		before := mustReadFile(t, path)
		var stderr bytes.Buffer
		cmd := hermesCmd(py, dir, "-c", hermesLoad, dir, "EXAMPLE_API_KEY")
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("Hermes loader: %v", err)
		}
		if len(out) == 0 || out[0] != '=' {
			t.Fatalf("Hermes loader dropped the variable for %q (%d bytes back)", v, len(out))
		}
		got, err := fingerprint.Compute(key, newValue(string(out[1:])))
		if err != nil {
			t.Fatal(err)
		}
		if got != fp {
			t.Errorf("Hermes loader reads a different value than was written for %q", v)
		}
		if after := mustReadFile(t, path); !bytes.Equal(after, before) {
			t.Errorf("Hermes loader rewrote the file for %q", v)
		}
		if stderr.Len() != 0 {
			t.Errorf("Hermes loader printed to stderr for %q", v)
		}
		second := hermesCmd(py, dir, "-c", hermesLoadEnv, "EXAMPLE_API_KEY")
		out2, err := second.Output()
		if err != nil {
			t.Fatalf("Hermes load_env: %v", err)
		}
		if string(out2) != string(out) {
			t.Errorf("Hermes load_env reads a different value than load_hermes_dotenv for %q", v)
		}
	}
	for _, n := range []string{"FIRST", "LAST"} {
		out, err := hermesCmd(py, dir, "-c", hermesLoad, dir, n).Output()
		if err != nil || len(out) == 0 || out[0] != '=' {
			t.Errorf("neighbor %s lost to the Hermes loader: %v (%d bytes back)", n, err, len(out))
		}
	}
}

// The name-run rule stands in for the loader's list of Hermes variable names.
// Every name on that list, in front of an equals sign inside a value, must be
// refused, and every name as the field with a plain value must leave the file
// unrewritten. If a Hermes release adds a name shorter than the rule's run,
// this test goes red.
func TestHermesConfigRefusesEveryKnownKeyInValue(t *testing.T) {
	py := hermesPython(t)
	const listNames = `from hermes_cli.config import OPTIONAL_ENV_VARS, _EXTRA_ENV_KEYS
print("\n".join(sorted(set(OPTIONAL_ENV_VARS) | _EXTRA_ENV_KEYS)))`
	out, err := hermesCmd(py, t.TempDir(), "-c", listNames).Output()
	if err != nil {
		t.Fatalf("list Hermes variable names: %v", err)
	}
	names := strings.Fields(string(out))
	if len(names) < 100 {
		t.Fatalf("only %d Hermes variable names listed: the probe is broken", len(names))
	}
	uids, gids := noAgents()
	for _, n := range names {
		if len(n) <= hermesNameRun {
			t.Errorf("Hermes variable %s is not longer than the name run %d: the rule would miss it", n, hermesNameRun)
		}
		path := filepath.Join(realDir(t), ".env")
		_, err := Write(target(runnerproto.TargetHermesConfig, path, "EXAMPLE_API_KEY"), newValue("x"+n+"=y"), uids, gids, testFPKey(t))
		if err == nil {
			t.Errorf("value planting %s accepted", n)
		}
	}
	// Every name as the field of its own line, one Write each, then one load of
	// the whole file: the loader must not rewrite it and must see every line.
	dir := realDir(t)
	path := filepath.Join(dir, ".env")
	for _, n := range names {
		if _, err := Write(target(runnerproto.TargetHermesConfig, path, n), newValue("plainvalue"), uids, gids, testFPKey(t)); err != nil {
			t.Fatalf("field %s: %v", n, err)
		}
	}
	before := mustReadFile(t, path)
	args := append([]string{"-c", `import os, sys
from hermes_cli.env_loader import load_hermes_dotenv
load_hermes_dotenv(hermes_home=sys.argv[1], project_env=os.path.join(sys.argv[1], "none.env"))
print(sum(1 for n in sys.argv[2:] if os.environ.get(n) == "plainvalue"))`, dir}, names...)
	loaded, err := hermesCmd(py, dir, args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReadFile(t, path), before) {
		t.Error("Hermes loader rewrote a file of plain NAME=value lines")
	}
	if got := strings.TrimSpace(string(loaded)); got != strconv.Itoa(len(names)) {
		t.Errorf("Hermes loader read %s of %d variables", got, len(names))
	}
}
