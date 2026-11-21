package runnerproto

import (
	"strings"
	"testing"
)

func TestYAMLTargetIsReadOnlyAndExact(t *testing.T) {
	j := deployJob(t)
	j.Target.Kind, j.Target.Field = TargetYAMLScalar, "mcp_servers.bridge.env.API_KEY"
	if err := j.Validate(); err == nil {
		t.Fatal("YAML deploy accepted")
	}
	j.Action = ActionVerify
	if err := j.Validate(); err != nil {
		t.Fatal("YAML verify refused")
	}
	for _, field := range []string{"", "a..b", "a[0].key", "a.*", ".key", strings.Repeat("a", 257), strings.Repeat("a.", 16) + "a"} {
		j.Target.Field = field
		if err := j.Validate(); err == nil {
			t.Fatal("ambiguous YAML field accepted")
		}
	}
}

func TestYAMLDiscoveryPolicyUsesExactDottedNames(t *testing.T) {
	d := goodDiscovery()
	d.Roots[0].Rules[0] = DiscoveryRule{Kind: string(TargetYAMLScalar), Glob: "*.yaml", Names: []string{"mcp_servers.bridge.env.API_KEY"}}
	if err := policyWith(d).Validate(); err != nil {
		t.Fatal("exact YAML discovery policy refused")
	}
	for _, field := range []string{"a..b", "a.*", "a[0].key", strings.Repeat("a", 257)} {
		d.Roots[0].Rules[0].Names = []string{field}
		if err := policyWith(d).Validate(); err == nil {
			t.Fatal("ambiguous YAML discovery field accepted")
		}
	}
	d.Roots[0].Rules[0].Kind = "env-file"
	d.Roots[0].Rules[0].Names = []string{"service.API_KEY"}
	if err := policyWith(d).Validate(); err == nil {
		t.Fatal("YAML fields changed env-file policy semantics")
	}
}
