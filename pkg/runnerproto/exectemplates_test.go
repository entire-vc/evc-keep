package runnerproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
)

func execPolicy() HostPolicy {
	return HostPolicy{
		Version: 1, MaxDeploysPerHour: 10, AllowExec: true,
		ExecBinDirs: []string{"/opt/keep-exec/bin"},
		ExecTemplates: []ExecTemplate{{
			ID:        "tool-run",
			Argv:      []string{"/opt/keep-exec/bin/tool", "--id", "{id}"},
			Params:    map[string]ExecParam{"id": {Pattern: `^[a-z0-9]{1,16}$`}},
			SecretEnv: []string{"TOOL_KEY"},
			Network:   ExecNetwork{Mode: "none"},
		}},
	}
}

func TestHostPolicyExecTemplatesValid(t *testing.T) {
	if err := execPolicy().Validate(); err != nil {
		t.Fatalf("valid exec policy refused: %v", err)
	}
}

// The runner re-validates every template by the same rules the server
// applies, so a hand-edited policy file cannot carry a launcher or a network
// client into a network-none template.
func TestHostPolicyRefusesBadExecTemplates(t *testing.T) {
	cases := map[string]func(*HostPolicy){
		"interpreter":               func(p *HostPolicy) { p.ExecTemplates[0].Argv[0] = "/opt/keep-exec/bin/python3" },
		"network-client":            func(p *HostPolicy) { p.ExecTemplates[0].Argv[0] = "/opt/keep-exec/bin/curl" },
		"bad-id":                    func(p *HostPolicy) { p.ExecTemplates[0].ID = "Tool Run" },
		"duplicate-id":              func(p *HostPolicy) { p.ExecTemplates = append(p.ExecTemplates, p.ExecTemplates[0]) },
		"unknown-mode":              func(p *HostPolicy) { p.ExecTemplates[0].Network.Mode = "any" },
		"empty-secret-env":          func(p *HostPolicy) { p.ExecTemplates[0].SecretEnv = nil },
		"loose-param":               func(p *HostPolicy) { p.ExecTemplates[0].Params["id"] = ExecParam{Pattern: `^.*$`} },
		"relative-bindir":           func(p *HostPolicy) { p.ExecBinDirs = []string{"bin"} },
		"root-bindir":               func(p *HostPolicy) { p.ExecBinDirs = []string{"/"} },
		"unclean-bindir":            func(p *HostPolicy) { p.ExecBinDirs = []string{"/opt/keep-exec/../bin"} },
		"templates-without-bindirs": func(p *HostPolicy) { p.ExecBinDirs = nil },
		"templates-without-allow":   func(p *HostPolicy) { p.AllowExec = false },
	}
	for name, mutate := range cases {
		p := execPolicy()
		p.ExecTemplates = append([]ExecTemplate(nil), p.ExecTemplates...)
		p.ExecTemplates[0].Argv = append([]string(nil), p.ExecTemplates[0].Argv...)
		mutate(&p)
		if p.Validate() == nil {
			t.Errorf("%s: policy accepted", name)
		}
	}
}

func TestExecTemplateConvertsToExecpolicy(t *testing.T) {
	p := execPolicy()
	p.ExecTemplates[0].Network = ExecNetwork{Mode: "allowlist", Destinations: []ExecDestination{{Host: "api.example.com", Port: 443}}}
	tpl, ok := p.ExecTemplate("tool-run")
	if !ok || tpl.Network.Mode != execpolicy.NetAllowlist || tpl.Network.Destinations[0].Port != 443 {
		t.Fatalf("conversion lost the network section: %+v ok=%v", tpl, ok)
	}
	if _, ok := p.ExecTemplate("nope"); ok {
		t.Fatal("unknown template found")
	}
}

func TestHostPolicyExecTemplatesJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(execPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var back HostPolicy
	if err := json.Unmarshal(b, &back); err != nil || back.Validate() != nil {
		t.Fatalf("round trip: %v %v", err, back.Validate())
	}
	if !strings.Contains(string(b), `"exec_templates"`) || !strings.Contains(string(b), `"exec_bin_dirs"`) {
		t.Fatalf("policy file keys missing: %s", b)
	}
}
