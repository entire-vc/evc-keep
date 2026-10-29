//go:build unix

package targets

import (
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/carriers/meshkey"
)

// TestVerifyReadsEveryMeshKeyCarrier: the locators meshkey publishes resolve,
// through Verify, to the one key in each of the four fixture carriers and to
// nothing else (a different agent's key in the same file is a mismatch).
func TestVerifyReadsEveryMeshKeyCarrier(t *testing.T) {
	f := newVerifyFixture(t)
	dir := f.dir
	reg := fmt.Sprintf(`{"agents":[{"name":"Other","agent_key":%q,"mesh_agent_key":%q},{"name":"Sage","agent_key":%q,"mesh_agent_key":%q}]}`,
		f.others[0], f.others[1], f.target, f.target)
	f.write(t, "mesh-agents.json", reg)
	f.write(t, "fiddler.json", reg)
	f.write(t, ".mcp.json", fmt.Sprintf(`{"mcpServers":{"evc-mesh":{"env":{"MESH_AGENT_KEY":%q}}}}`, f.target))
	f.write(t, "sage.env", fmt.Sprintf("OTHER=%s\nMESH_AGENT_KEY=%s\n", f.others[0], f.target))
	cs, err := meshkey.For(meshkey.Agent{Host: "h", Name: "Sage", LaneDir: dir, BinDir: dir, CfgDir: dir, EnvDir: dir, EnvFile: "sage.env"})
	if err != nil {
		t.Fatal(err)
	}
	good, other := f.fp(t, f.target), f.fp(t, f.others[0])
	for _, c := range cs {
		spec := readSpec{Format: readFormat(c.Format), Path: c.Path, Field: c.Field}
		if got, err := verifySpec(spec, good, f.key); err != nil || got != VerifyMatch {
			t.Errorf("%s: got %q %v", c.Kind, got, err)
		}
		if got, err := verifySpec(spec, other, f.key); err != nil || got != VerifyMismatch {
			t.Errorf("%s with another key: got %q %v", c.Kind, got, err)
		}
	}
}
