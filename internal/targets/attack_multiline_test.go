//go:build unix

package targets_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// A quoted value that spans lines belongs to its variable; a line inside it
// that starts with the field name is not the field's line. The writer must
// either leave the neighbour's bytes alone or refuse, never rewrite the line
// inside it: the read back is line based too, so it would confirm a write that
// the consumer reads as a different file (the neighbour cut open, the new value
// swallowed by it).
func TestTargetsAttack_MultilineQuotedNeighbourIsNotRewritten(t *testing.T) {
	neighbour := []byte("A='x\nNAME=inside'\n")
	for _, kind := range []runnerproto.TargetKind{runnerproto.TargetEnvFile, runnerproto.TargetHermesConfig} {
		t.Run(string(kind), func(t *testing.T) {
			// positive control: the same call on a plain layout succeeds and
			// keeps the neighbour, so a refusal below is not "always refuses".
			pc := filepath.Join(dir(t), "pc.env")
			if err := os.WriteFile(pc, []byte("A=1\nNAME=old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := targets.Write(tgt(kind, pc, "NAME"), secret.New([]byte("newvalue")), nil, nil, fpKey(t)); err != nil {
				t.Fatalf("positive control refused: %v", err)
			}
			pcGot, _ := os.ReadFile(pc) //nolint:gosec // G304: test-controlled path
			if !bytes.HasPrefix(pcGot, []byte("A=1\n")) {
				t.Fatalf("positive control lost its neighbour")
			}

			p := filepath.Join(dir(t), "app.env")
			if err := os.WriteFile(p, append(append([]byte{}, neighbour...), "OTHER=1\n"...), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := targets.Write(tgt(kind, p, "NAME"), secret.New([]byte("newvalue")), nil, nil, fpKey(t))
			if err != nil {
				return // refusing is a fine answer
			}
			got, rerr := os.ReadFile(p) //nolint:gosec // G304: test-controlled path
			if rerr != nil {
				t.Fatal(rerr)
			}
			if !bytes.Contains(got, neighbour) {
				t.Fatalf("the multi-line neighbour was rewritten and Write reported success (file is %d bytes)", len(got))
			}
		})
	}
}
