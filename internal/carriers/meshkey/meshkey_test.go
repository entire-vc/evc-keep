package meshkey

import (
	"errors"
	"strings"
	"testing"
)

func agent() Agent {
	return Agent{Host: "mini", Name: "Sage", LaneDir: "/w/sage", BinDir: "/h/bin", CfgDir: "/h/.config/fiddler",
		EnvDir: "/h/.config/agents", EnvFile: "sage.env"}
}

func TestForDescribesFourCarriers(t *testing.T) {
	cs, err := For(agent())
	if err != nil || len(cs) != 4 {
		t.Fatalf("got %d carriers, err %v", len(cs), err)
	}
	want := []struct {
		k           Kind
		f, p, field string
	}{
		{MCPJSON, FormatJSON, "/w/sage/.mcp.json", "mcpServers.evc-mesh.env.MESH_AGENT_KEY"},
		{MeshAgents, FormatJSON, "/h/bin/mesh-agents.json", "agents[name=Sage].agent_key"},
		{FiddlerJSON, FormatJSON, "/h/.config/fiddler/fiddler.json", "agents[name=Sage].mesh_agent_key"},
		{AgentEnv, FormatEnv, "/h/.config/agents/sage.env", "MESH_AGENT_KEY"},
	}
	for i, w := range want {
		c := cs[i]
		if c.Kind != w.k || c.Format != w.f || c.Path != w.p || c.Field != w.field ||
			c.Metadata.TargetPath != w.p || c.Metadata.TargetField != w.field || c.Metadata.Host != "mini" {
			t.Errorf("carrier %d = %+v, want %+v", i, c, w)
		}
	}
}

func TestForRefusesSelectorWideningAndBadPaths(t *testing.T) {
	for name, mut := range map[string]func(*Agent){
		"bracket-in-name":  func(a *Agent) { a.Name = "x].agent_key" },
		"dot-path-in-name": func(a *Agent) { a.Name = "a/../b" },
		"dot-in-name":      func(a *Agent) { a.Name = "a.b" },
		"empty-name":       func(a *Agent) { a.Name = "" },
		"equals-in-name":   func(a *Agent) { a.Name = "a=b" },
		"relative-lane":    func(a *Agent) { a.LaneDir = "w/sage" },
		"unclean-bin":      func(a *Agent) { a.BinDir = "/h/bin/../x" },
		"env-file-slash":   func(a *Agent) { a.EnvFile = "../keys.env" },
		"bad-var":          func(a *Agent) { a.EnvVar = "A B" },
		"no-host":          func(a *Agent) { a.Host = "" },
	} {
		a := agent()
		mut(&a)
		if _, err := For(a); !errors.Is(err, ErrAgent) {
			t.Errorf("%s: want ErrAgent, got %v", name, err)
		}
	}
	a := agent()
	a.Name = strings.Repeat("a", 65)
	if _, err := For(a); !errors.Is(err, ErrAgent) {
		t.Errorf("long name accepted")
	}
}

// TestMemberAcceptsOnlyTheManifest: every carrier For produces is a member;
// a carrier moved to another file name, field or kind is not.
func TestMemberAcceptsOnlyTheManifest(t *testing.T) {
	cs, err := For(Agent{Host: "h", Name: "Sage", LaneDir: "/l", BinDir: "/b", CfgDir: "/c", EnvDir: "/e", EnvFile: "sage.env"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if !c.Member() {
			t.Errorf("%s from For is not a member", c.Kind)
		}
	}
	for name, mut := range map[string]func(*Carrier){
		"other file":  func(c *Carrier) { c.Path = "/etc/passwd"; c.Metadata.TargetPath = c.Path },
		"other field": func(c *Carrier) { c.Field = "x"; c.Metadata.TargetField = "x" },
		"other kind":  func(c *Carrier) { c.Kind = "shadow" },
		"relative":    func(c *Carrier) { c.Path = "rel/.mcp.json"; c.Metadata.TargetPath = c.Path },
	} {
		c := cs[0]
		mut(&c)
		if c.Member() {
			t.Errorf("%s: still a member", name)
		}
	}
	if (Carrier{}).Member() {
		t.Error("zero carrier is a member")
	}
}

// An agent env file is a carrier only for the Mesh agent key variable: any
// other name would make Verify a fingerprint oracle over the neighbours in
// the same file.
func TestMemberAgentEnvKeepsOnlyTheAgentKeyVariable(t *testing.T) {
	cs, err := For(Agent{Host: "h", Name: "Sage", LaneDir: "/l", BinDir: "/b", CfgDir: "/c", EnvDir: "/e", EnvFile: "sage.env"})
	if err != nil {
		t.Fatal(err)
	}
	c := cs[3]
	if c.Kind != AgentEnv || !c.Member() {
		t.Fatal("positive control: the agent env carrier is not a member")
	}
	for _, field := range []string{"DB_PASSWORD", "OTHER", "mesh_agent_key", "MESH_AGENT_KEY2"} {
		d := c
		d.Field, d.Metadata.TargetField = field, field
		if d.Member() {
			t.Errorf("variable %q is a member", field)
		}
	}
	if _, err := For(Agent{Host: "h", Name: "Sage", LaneDir: "/l", BinDir: "/b", CfgDir: "/c", EnvDir: "/e", EnvFile: "sage.env", EnvVar: "DB_PASSWORD"}); err == nil {
		t.Error("For describes a carrier for another variable")
	}
}
