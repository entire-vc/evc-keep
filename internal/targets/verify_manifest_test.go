//go:build unix

package targets

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/carriers/meshkey"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// countOpens swaps the open seam for one that counts how many files Verify
// tried to open; the real open still happens so allowed carriers work.
func countOpens(t *testing.T) *int {
	t.Helper()
	n := 0
	prev := openCarrier
	openCarrier = func(dirfd int, p string, flags int, mode uint32) (int, error) {
		n++
		return prev(dirfd, p, flags, mode)
	}
	t.Cleanup(func() { openCarrier = prev })
	return &n
}

func (f *verifyFixture) agentCarriers(t *testing.T) []meshkey.Carrier {
	t.Helper()
	reg := fmt.Sprintf(`{"agents":[{"name":"Sage","agent_key":%q,"mesh_agent_key":%q},{"name":"Other","agent_key":%q,"mesh_agent_key":%q}]}`,
		f.target, f.target, f.others[0], f.others[1])
	f.write(t, "mesh-agents.json", reg)
	f.write(t, "fiddler.json", reg)
	f.write(t, ".mcp.json", fmt.Sprintf(`{"mcpServers":{"evc-mesh":{"env":{"MESH_AGENT_KEY":%q}}}}`, f.target))
	f.write(t, "sage.env", fmt.Sprintf("OTHER=%s\nMESH_AGENT_KEY=%s\n", f.others[0], f.target))
	cs, err := meshkey.For(meshkey.Agent{Host: "h", Name: "Sage", LaneDir: f.dir, BinDir: f.dir, CfgDir: f.dir, EnvDir: f.dir, EnvFile: "sage.env"})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// TestVerifyCarrierAcceptsOnlyManifestCarriers: the four carriers meshkey
// publishes are verified (positive control); everything else is refused with
// a policy error BEFORE any file is opened, and the error echoes nothing the
// caller supplied.
func TestVerifyCarrierAcceptsOnlyManifestCarriers(t *testing.T) {
	f := newVerifyFixture(t)
	cs := f.agentCarriers(t)
	good := f.fp(t, f.target)
	opens := countOpens(t)

	for _, c := range cs {
		before := *opens
		got, err := VerifyCarrier([]string{f.dir}, 1, c, good, f.key)
		if err != nil || got != VerifyMatch {
			t.Fatalf("positive control %s: got %q %v", c.Kind, got, err)
		}
		if *opens != before+1 {
			t.Fatalf("positive control %s: expected exactly one open, got %d", c.Kind, *opens-before)
		}
	}

	// A readable file with a canary, reachable by absolute path, that is no
	// carrier of the manifest.
	foreign := f.write(t, "notes.txt", "K="+f.target+"\n")
	foreignJSON := f.write(t, "other.json", fmt.Sprintf(`{"agents":[{"name":"Sage","agent_key":%q}]}`, f.target))
	mk := func(k meshkey.Kind, format, p, field string) meshkey.Carrier {
		kind := runnerproto.TargetMCPConfig
		if format == meshkey.FormatEnv {
			kind = runnerproto.TargetEnvFile
		}
		c := cs[0]
		c.Kind, c.Format, c.Path, c.Field = k, format, p, field
		c.Metadata.TargetKind, c.Metadata.TargetPath, c.Metadata.TargetField = kind, p, field
		return c
	}
	bad := map[string]meshkey.Carrier{
		"foreign env file":           mk(meshkey.AgentEnv, meshkey.FormatEnv, foreign, "K"),
		"foreign json file":          mk(meshkey.MeshAgents, meshkey.FormatJSON, foreignJSON, "agents[name=Sage].agent_key"),
		"etc passwd":                 mk(meshkey.AgentEnv, meshkey.FormatEnv, "/etc/passwd", "root"),
		"field outside the manifest": mk(meshkey.MCPJSON, meshkey.FormatJSON, cs[0].Path, "mcpServers.evc-mesh.env.OTHER"),
		"wrong field for the file":   mk(meshkey.MeshAgents, meshkey.FormatJSON, cs[1].Path, "agents[name=Sage].mesh_agent_key"),
		"unknown kind":               mk(meshkey.Kind("shadow"), meshkey.FormatJSON, cs[0].Path, cs[0].Field),
		"format mismatch":            mk(meshkey.MCPJSON, meshkey.FormatEnv, cs[0].Path, cs[0].Field),
		"traversal in path":          mk(meshkey.MCPJSON, meshkey.FormatJSON, f.dir+"/x/../.mcp.json", cs[0].Field),
		"env var with separator":     mk(meshkey.AgentEnv, meshkey.FormatEnv, cs[3].Path, "MESH_AGENT_KEY\nOTHER"),
		"metadata path differs":      func() meshkey.Carrier { c := cs[0]; c.Metadata.TargetPath = foreign; return c }(),
		"metadata field differs":     func() meshkey.Carrier { c := cs[0]; c.Metadata.TargetField = "x"; return c }(),
		"zero carrier":               {},
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			before := *opens
			got, err := VerifyCarrier([]string{f.dir}, 1, c, good, f.key)
			if !errors.Is(err, ErrPolicy) || got != "" {
				t.Fatalf("got %q %v, want ErrPolicy", got, err)
			}
			if *opens != before {
				t.Fatalf("a file was opened for a carrier outside the manifest (%d opens)", *opens-before)
			}
			msg := err.Error()
			for _, echo := range []string{c.Path, c.Field, filepath.Base(c.Path), string(c.Kind)} {
				if len(echo) > 3 && strings.Contains(msg, echo) {
					t.Fatalf("error echoes caller input %q: %q", echo, msg)
				}
			}
			if f.seen(msg) {
				t.Fatalf("secret in error: %q", msg)
			}
		})
	}
}
