//go:build unix

//nolint:gosec,errcheck // attack fixtures live in a temp dir, setup errors are irrelevant to the assertion, and the fuzz seed must be reproducible
package targets_test

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Differential attack on hermes-config: the Hermes loaders (both readers of
// the file) must see, after a Write, exactly the written value for the field,
// exactly the values they saw before for every neighbour, must not rewrite
// the file, and must print nothing to stderr — or the writer must refuse.
//
// Local-only guard: needs KEEP_HERMES_PYTHON (a real Hermes venv on the
// developer's machine), which nothing sets in CI — it is not installed
// there and this test SKIPs there on purpose (CI running Hermes is out of
// scope; see the MR's "Local-only guards" section). Run it by hand before
// touching internal/targets/hermesenv.go: KEEP_HERMES_PYTHON=<path to a
// venv's python with hermes_cli installed> go test -run
// TestTargetsAttack_HermesDifferentialLoader ./internal/targets/.

const hermesProbe = `import json, os, sys, hashlib
from hermes_cli.env_loader import load_hermes_dotenv
from hermes_cli.config import load_env
home = sys.argv[1]
names = sys.argv[2:]
for n in names:
    os.environ.pop(n, None)
load_hermes_dotenv(hermes_home=home, project_env=os.path.join(home, "none.env"))
r1 = {n: os.environ.get(n) for n in names}
r2 = load_env()
r2 = {n: r2.get(n) for n in names}
h = hashlib.sha256(open(os.path.join(home, ".env"), "rb").read()).hexdigest()
sys.stdout.write(json.dumps({"r1": r1, "r2": r2, "h": h}))`

func hermesRead(t *testing.T, py, home string, names []string) (map[string]map[string]*string, string, string) {
	t.Helper()
	// A hostile written line is the whole point of this fuzz: one that makes
	// Hermes's own loader hang must fail this iteration, not eat the rest of
	// the job's time budget.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, py, append([]string{"-c", hermesProbe, home}, names...)...)
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "HERMES_HOME=" + home}
	var so, se bytes.Buffer
	c.Stdout, c.Stderr = &so, &se
	if err := c.Run(); err != nil {
		t.Fatalf("hermes probe: %v", err)
	}
	var out struct {
		R1 map[string]*string `json:"r1"`
		R2 map[string]*string `json:"r2"`
		H  string             `json:"h"`
	}
	if err := json.Unmarshal(so.Bytes(), &out); err != nil {
		t.Fatalf("probe output: %v", err)
	}
	return map[string]map[string]*string{"r1": out.R1, "r2": out.R2}, out.H, se.String()
}

func TestTargetsAttack_HermesDifferentialLoader(t *testing.T) {
	py := os.Getenv("KEEP_HERMES_PYTHON")
	if py == "" {
		t.Skip("KEEP_HERMES_PYTHON not set")
	}
	iters := 150
	if s := os.Getenv("KEEP_ATTACK_FUZZ_ITERS"); s != "" {
		iters, _ = strconv.Atoi(s)
	}
	seed := int64(77)
	if s := os.Getenv("KEEP_ATTACK_FUZZ_SEED"); s != "" {
		seed, _ = strconv.ParseInt(s, 10, 64)
	}
	r := rand.New(rand.NewSource(seed))
	alpha := []string{"a", "Z", "0", "_", "-", "/", ".", ":", "@", "%", "+", ",", " ", "#", "$", "`", "=", ";", "&", "|", "<", ">", "(", ")", "{", "}", "[", "]", "*", "?", "!", "~", "^", "A_B", "OPENAI_API_KEY=", "TELEGRAM_BOT_TOKEN=", "KEY=", "  ", "export ", "\t", "\xc3\xa9", "'", "\"", "\\"}
	nalpha := []string{"A", "FOO", "OPENAI_API_KEY", "TELEGRAM_BOT_TOKEN", "EXAMPLE_API_KEY", "OPENROUTER_API_KEY", "GITHUB_TOKEN", "x_lower", "B2"}
	fields := []string{"EXAMPLE_API_KEY", "FOO", "OPENAI_API_KEY"}
	names := append(append([]string{}, nalpha...), fields...)
	gen := func(n int) string {
		var b strings.Builder
		for i := r.Intn(n) + 1; i > 0; i-- {
			b.WriteString(alpha[r.Intn(len(alpha))])
		}
		return b.String()
	}
	wrote, bad := 0, 0
	for i := 0; i < iters && bad < 4; i++ {
		home := dir(t)
		field := fields[r.Intn(len(fields))]
		var lines []string
		for j := r.Intn(4); j > 0; j-- {
			switch r.Intn(4) {
			case 0:
				lines = append(lines, nalpha[r.Intn(len(nalpha))]+"="+gen(4))
			case 1:
				lines = append(lines, nalpha[r.Intn(len(nalpha))]+"='"+gen(3)+"'")
			case 2:
				lines = append(lines, "# "+gen(3))
			default:
				lines = append(lines, nalpha[r.Intn(len(nalpha))]+"=plain"+strconv.Itoa(j))
			}
		}
		existing := ""
		if len(lines) > 0 {
			existing = strings.Join(lines, "\n") + "\n"
		}
		val := gen(6)
		if existing != "" {
			os.WriteFile(filepath.Join(home, ".env"), []byte(existing), 0o600)
		}
		var before map[string]map[string]*string
		if existing != "" {
			cp := dir(t)
			os.WriteFile(filepath.Join(cp, ".env"), []byte(existing), 0o600)
			var se string
			before, _, se = hermesRead(t, py, cp, names)
			if se != "" {
				continue // hostile neighbour already makes Hermes complain: not this writer's doing
			}
		}
		path := filepath.Join(home, ".env")
		_, err := targets.Write(tgt(runnerproto.TargetHermesConfig, path, field), secret.New([]byte(val)), nil, nil, fpKey(t))
		if err != nil {
			continue
		}
		wrote++
		file, _ := os.ReadFile(path)
		after, h1, se := hermesRead(t, py, home, names)
		h2sum, _ := os.ReadFile(path)
		fieldLine := func(b []byte) string {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, field+"=") {
					return l
				}
			}
			return "<none>"
		}
		// The loader normalises hostile neighbours by itself (trailing blanks);
		// what must stay put is the line this package wrote.
		if fieldLine(file) != fieldLine(h2sum) {
			bad++
			t.Errorf("iter %d: the Hermes loader rewrote the written line\nexisting=%q value=%q\nbefore=%q\nafter=%q", i, existing, val, file, h2sum)
			continue
		}
		_ = h1
		if se != "" {
			bad++
			t.Errorf("iter %d: Hermes printed to stderr after the write (%d bytes)\nexisting=%q value=%q file=%q", i, len(se), existing, val, file)
			continue
		}
		for _, rd := range []string{"r1", "r2"} {
			got := after[rd][field]
			if got == nil || *got != val {
				bad++
				g := "<nil>"
				if got != nil {
					g = *got
				}
				t.Errorf("iter %d: %s reads %q for %s, wrote %q\nexisting=%q file=%q", i, rd, g, field, val, existing, file)
				continue
			}
			for _, n := range names {
				if n == field || before == nil {
					continue
				}
				b, a := before[rd][n], after[rd][n]
				if (b == nil) != (a == nil) || (b != nil && *b != *a) {
					bad++
					t.Errorf("iter %d: %s neighbour %s changed by the write\nexisting=%q value=%q\nfile=%q", i, rd, n, existing, val, file)
					break
				}
			}
		}
	}
	t.Logf("iters=%d wrote=%d bad=%d seed=%d", iters, wrote, bad, seed)
	if wrote < iters/10 {
		t.Fatalf("positive control failed: only %d writes accepted", wrote)
	}
}
