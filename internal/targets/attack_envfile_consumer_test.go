//go:build unix

package targets_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// What a shell consumer (`set -a; . file`) sees for values the writer accepts.
func TestTargetsAttack_EnvFileConsumerSeesSameValue(t *testing.T) {
	for name, v := range map[string]string{"space": "a b", "semicolon": "a;touch PWNED", "dollar": "a$HOME", "quote": `"abc"`, "hash": "a #b", "backslash-end": `abc\`, "backtick": "a`id`"} {
		t.Run(name, func(t *testing.T) {
			d := dir(t)
			p := filepath.Join(d, "svc.env")
			ok(t, os.WriteFile(p, []byte("A=1\n"), 0o600))
			if _, err := targets.Write(tgt(runnerproto.TargetEnvFile, p, "NAME"), secret.New([]byte(v)), nil, nil, fpKey(t)); err != nil {
				t.Logf("refused: %v", err)
				return
			}
			c := exec.Command("sh", "-c", `set -a; . ./svc.env >/dev/null 2>&1; printf '%s' "$NAME"`)
			c.Dir = d
			c.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"} // not the runner's environment
			out, _ := c.Output()
			_, statErr := os.Stat(filepath.Join(d, "PWNED"))
			if string(out) != v || statErr == nil {
				t.Errorf("shell consumer sees a different value (%d bytes, want %d); command executed=%v", len(out), len(v), statErr == nil)
			}
		})
	}
}
