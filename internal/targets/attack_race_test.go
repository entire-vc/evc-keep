//go:build unix

//nolint:gosec,errcheck // attack fixtures live in a temp dir, setup errors are irrelevant to the assertion, and the fuzz seed must be reproducible
package targets_test

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// A hostile process flips a directory on the target's path between the real
// directory and a symlink to a decoy tree while Write runs in a loop. The
// decoy must never receive the value, for any kind, and the real target must
// only ever hold complete content.
func TestTargetsAttack_LiveSymlinkFlipNeverEscapes(t *testing.T) {
	for _, kind := range []runnerproto.TargetKind{runnerproto.TargetFile, runnerproto.TargetEnvFile, runnerproto.TargetMCPConfig} {
		t.Run(string(kind), func(t *testing.T) {
			root := dir(t)
			real := filepath.Join(root, "real")
			decoy := filepath.Join(root, "decoy")
			for _, p := range []string{real, decoy} {
				os.MkdirAll(filepath.Join(p, "sub"), 0o700)
			}
			name := "f"
			field := "NAME"
			body := []byte("A=1\n")
			switch kind {
			case runnerproto.TargetMCPConfig:
				name, field = "f.json", "mcpServers.s.env.TOK"
				body = []byte(`{"mcpServers":{"s":{"env":{}}}}`)
			case runnerproto.TargetFile:
				body, field = nil, ""
			}
			for _, p := range []string{real, decoy} {
				if body != nil {
					os.WriteFile(filepath.Join(p, "sub", name), body, 0o600)
				}
			}
			// The component under attack is a real directory that a hostile process
			// keeps replacing by a symlink to the decoy tree and back.
			link := filepath.Join(root, "swap")
			aside := filepath.Join(root, "aside")
			os.Rename(real, link)
			// Deterministic controls, independent of the race: with the component a
			// real directory a write must be accepted, with it a symlink to the decoy
			// it must be refused. The live flip below then only has to keep the
			// invariants; it is not trusted to hit both states.
			cp := filepath.Join(link, "sub", name)
			if _, err := targets.Write(tgt(kind, cp, field), secret.New([]byte(canary)), nil, nil, fpKey(t)); err != nil {
				t.Fatalf("control: write through a real directory must be accepted: %v", err)
			}
			os.Rename(link, aside)
			os.Symlink(decoy, link)
			if _, err := targets.Write(tgt(kind, cp, field), secret.New([]byte(canary)), nil, nil, fpKey(t)); err == nil {
				t.Fatalf("control: write through a symlinked component must be refused")
			}
			os.Remove(link)
			os.Rename(aside, link)
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if os.Rename(link, aside) != nil {
						continue
					}
					_ = os.Symlink(decoy, link)
					_ = os.Remove(link)
					_ = os.Rename(aside, link)
				}
			}()
			var wrote, refused int64
			deadline := time.Now().Add(2500 * time.Millisecond)
			for time.Now().Before(deadline) {
				p := filepath.Join(link, "sub", name)
				_, err := targets.Write(tgt(kind, p, field), secret.New([]byte(canary)), nil, nil, fpKey(t))
				if err == nil {
					atomic.AddInt64(&wrote, 1)
				} else {
					atomic.AddInt64(&refused, 1)
				}
			}
			close(stop)
			wg.Wait()
			// Every path component here is a symlink half the time: a refusal is the
			// expected outcome. Nothing may have been created or changed under decoy
			// or real through the symlink — the symlink never resolves for a write.
			for _, p := range []string{link, decoy} {
				ents, _ := os.ReadDir(filepath.Join(p, "sub"))
				for _, e := range ents {
					b, _ := os.ReadFile(filepath.Join(p, "sub", e.Name()))
					if p == decoy && string(b) != string(body) {
						t.Errorf("decoy %s changed: %d bytes", e.Name(), len(b))
					}
					if p == link && len(b) > 0 && !bytesHasNoTear(kind, b) {
						t.Errorf("real target torn: %s", redact(b))
					}
				}
			}
			t.Logf("wrote=%d refused=%d", wrote, refused)
		})
	}
}

// bytesHasNoTear: a successful write leaves either the original or complete new content.
func bytesHasNoTear(kind runnerproto.TargetKind, b []byte) bool {
	switch kind {
	case runnerproto.TargetFile:
		return string(b) == canary
	case runnerproto.TargetEnvFile:
		s := string(b)
		return s == "A=1\n" || s == "A=1\nNAME="+"'"+canary+"'"+"\n" || s == "A=1\nNAME="+canary+"\n"
	default:
		return len(b) > 0 && b[0] == '{' && b[len(b)-1] == '}' || b[len(b)-1] == '\n'
	}
}
