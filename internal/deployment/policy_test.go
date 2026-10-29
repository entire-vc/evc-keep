package deployment

import (
	"errors"
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

var policySecretID = uuid.UUID{1}

func TestPolicySecretBinding(t *testing.T) {
	p, h, target := policyFixture()
	if d, err := Evaluate(p, h, policySecretID, "dev", target, false); err != nil || d != Allow {
		t.Fatal("selected secret did not match")
	}
	if d, err := Evaluate(p, h, uuid.UUID{2}, "dev", target, false); err != nil || d != ApprovalRequired {
		t.Fatal("another secret inherited target template")
	}
	p.Rules[0].SecretID = uuid.Nil
	if d, err := Evaluate(p, h, policySecretID, "dev", target, false); err != nil || d != ApprovalRequired {
		t.Fatal("unbound rule acted as a wildcard")
	}
	if _, err := Evaluate(p, h, uuid.Nil, "dev", target, false); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("unresolved secret accepted")
	}
}

func policyFixture() (Policy, Host, runnerproto.Target) {
	return Policy{Rules: []Rule{{SecretID: policySecretID, RunnerID: "runner-a", Kind: runnerproto.TargetFile, PathPrefix: "/srv/app"}}},
		Host{ID: "runner-a", AttributesKnown: true},
		runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/srv/app/key", Mode: 0o600, UID: 1001, GID: 1001}
}

func TestPolicyDecisions(t *testing.T) {
	p, h, target := policyFixture()
	if d, err := Evaluate(p, h, policySecretID, "development", target, false); err != nil || d != Allow {
		t.Fatal("matching target refused")
	}
	if d, err := Evaluate(Policy{}, h, policySecretID, "development", target, false); err != nil || d != ApprovalRequired {
		t.Fatal("missing rule did not require approval")
	}
	for _, change := range []func(*Policy, *Host, *runnerproto.Target){
		func(_ *Policy, h *Host, _ *runnerproto.Target) { h.ID = "runner-b" },
		func(_ *Policy, _ *Host, target *runnerproto.Target) { target.Path = "/srv/application/key" },
		func(p *Policy, _ *Host, _ *runnerproto.Target) { p.Rules[0].Kind = runnerproto.TargetEnvFile },
	} {
		p, h, target := policyFixture()
		change(&p, &h, &target)
		if d, err := Evaluate(p, h, policySecretID, "development", target, false); err != nil || d != ApprovalRequired {
			t.Fatal("unmatched selector did not require approval")
		}
	}
}

func TestProductionHostAndNewTarget(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		for _, shared := range []bool{false, true} {
			p, h, target := policyFixture()
			h.AttributesKnown, h.UIDShared = trusted, shared
			d, err := Evaluate(p, h, policySecretID, "prod", target, true)
			if !trusted || shared {
				if !errors.Is(err, ErrPolicyDenied) {
					t.Fatal("unsafe production host accepted")
				}
			} else if err != nil || d != Allow {
				t.Fatal("trusted production carrier refused")
			}
		}
	}
	p, h, target := policyFixture()
	if d, err := Evaluate(p, h, policySecretID, "prod", target, false); err != nil || d != ApprovalRequired {
		t.Fatal("new production target accepted without approval")
	}
}

func TestTrustedLabelSelectors(t *testing.T) {
	p, h, target := policyFixture()
	p.Rules[0].RunnerID = ""
	p.Rules[0].Labels = map[string]string{"environment": "staging", "platform": "linux"}
	h.Labels = map[string]string{"environment": "staging", "platform": "linux"}
	if d, err := Evaluate(p, h, policySecretID, "development", target, false); err != nil || d != Allow {
		t.Fatal("matching labels refused")
	}
	h.Labels["platform"] = "darwin"
	if d, err := Evaluate(p, h, policySecretID, "development", target, false); err != nil || d != ApprovalRequired {
		t.Fatal("partial labels accepted")
	}
	h.AttributesKnown = false
	h.Labels["platform"] = "linux"
	if d, err := Evaluate(p, h, policySecretID, "development", target, false); err != nil || d != ApprovalRequired {
		t.Fatal("untrusted labels accepted")
	}
}

func TestPolicyRejectsNetworkAndTraversalWithoutEcho(t *testing.T) {
	c := canary.New()
	if !c.In(c.Value(0)) {
		t.Fatal("canary control failed")
	}
	for _, path := range []string{"https://example.invalid/" + c.Value(0), "/srv/app/host:443", "/srv/app/../outside", "/srv/app//key", "/srv/app/\n" + c.Value(0)} {
		p, h, target := policyFixture()
		target.Path = path
		_, err := Evaluate(p, h, policySecretID, "development", target, false)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("invalid target accepted")
		}
		if c.In(fmt.Sprint(err)) {
			t.Fatal("target leaked through policy error")
		}
	}
}

func TestInvalidPolicyFailsClosed(t *testing.T) {
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.Rules[0].RunnerID = "" },
		func(p *Policy) { p.Rules[0].PathPrefix = "/srv/app/.." },
		func(p *Policy) { p.Rules[0].Labels = map[string]string{"unrecognized": "value"} },
		func(p *Policy) { p.Rules[0].Labels = map[string]string{"platform": "unrecognized"} },
	} {
		p, h, target := policyFixture()
		mutate(&p)
		if _, err := Evaluate(p, h, policySecretID, "development", target, false); !errors.Is(err, ErrInvalidArgument) {
			t.Fatal("invalid policy accepted")
		}
	}
}
