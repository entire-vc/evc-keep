package runnerproto

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func goodDiscovery() *DiscoveryPolicy {
	return &DiscoveryPolicy{
		MaxPerHour: 4,
		Roots: []DiscoveryRoot{{
			Root: "/srv/app", TrustedUIDs: []int64{0, 1001}, MaxBytes: 1 << 16, MaxFiles: 16,
			Rules: []DiscoveryRule{{Glob: "*.env", Kind: "env-file", Names: []string{"STRIPE_KEY"}}},
		}},
	}
}

func policyWith(d *DiscoveryPolicy) HostPolicy {
	return HostPolicy{Version: 1, MaxDeploysPerHour: 1, AgentUIDs: []int64{1}, Discovery: d}
}

func TestDiscoveryPolicyValidate(t *testing.T) {
	if err := policyWith(goodDiscovery()).Validate(); err != nil {
		t.Fatalf("good policy: %v", err)
	}
	if err := policyWith(nil).Validate(); err != nil {
		t.Fatalf("no discovery section: %v", err)
	}
	for name, mod := range map[string]func(*DiscoveryPolicy){
		"no roots":        func(d *DiscoveryPolicy) { d.Roots = nil },
		"no hourly cap":   func(d *DiscoveryPolicy) { d.MaxPerHour = 0 },
		"cap too high":    func(d *DiscoveryPolicy) { d.MaxPerHour = 1000 },
		"relative root":   func(d *DiscoveryPolicy) { d.Roots[0].Root = "srv/app" },
		"filesystem root": func(d *DiscoveryPolicy) { d.Roots[0].Root = "/" },
		"dotdot root":     func(d *DiscoveryPolicy) { d.Roots[0].Root = "/srv/../etc" },
		"duplicate root":  func(d *DiscoveryPolicy) { d.Roots = append(d.Roots, d.Roots[0]) },
		"no trusted uid":  func(d *DiscoveryPolicy) { d.Roots[0].TrustedUIDs = nil },
		"agent uid":       func(d *DiscoveryPolicy) { d.Roots[0].TrustedUIDs = []int64{0, 1} },
		"negative uid":    func(d *DiscoveryPolicy) { d.Roots[0].TrustedUIDs = []int64{-1} },
		"no byte limit":   func(d *DiscoveryPolicy) { d.Roots[0].MaxBytes = 0 },
		"byte limit high": func(d *DiscoveryPolicy) { d.Roots[0].MaxBytes = 1 << 30 },
		"no file limit":   func(d *DiscoveryPolicy) { d.Roots[0].MaxFiles = 0 },
		"no rules":        func(d *DiscoveryPolicy) { d.Roots[0].Rules = nil },
		"unknown kind":    func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Kind = "shell-rc" },
		"empty glob":      func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Glob = "" },
		"no names":        func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Names = nil },
		"malformed name":  func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Names = []string{"A=B"} },
		"glob dotdot":     func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Glob = "../etc/*.env" },
		"glob absolute":   func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Glob = "/etc/*.env" },
		"glob recursive":  func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Glob = "**/*.env" },
		"glob tilde":      func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Glob = "~/*.env" },
		"duplicate name":  func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Names = []string{"A_KEY", "A_KEY"} },
		"credential names": func(d *DiscoveryPolicy) {
			d.Roots[0].Rules[0].Kind = "credential"
			d.Roots[0].Rules[0].Names = []string{"A", "B"}
		},
		"nested root": func(d *DiscoveryPolicy) {
			r := d.Roots[0]
			r.Root = "/srv/app/sub"
			d.Roots = append(d.Roots, r)
		},
		"file limit high": func(d *DiscoveryPolicy) { d.Roots[0].MaxFiles = maxDiscoveryFiles + 1 },
		"second name malformed": func(d *DiscoveryPolicy) {
			d.Roots[0].Rules[0].Names = []string{"A_KEY", "B=C"}
		},
		"too many names": func(d *DiscoveryPolicy) {
			var ns []string
			for i := 0; i <= maxDiscoveryNames; i++ {
				ns = append(ns, "N"+strconv.Itoa(i))
			}
			d.Roots[0].Rules[0].Names = ns
		},
		"too many rules": func(d *DiscoveryPolicy) {
			for i := 0; i <= maxDiscoveryRules; i++ {
				d.Roots[0].Rules = append(d.Roots[0].Rules, DiscoveryRule{Glob: "f" + strings.Repeat("a", i) + ".env", Kind: "env-file", Names: []string{"K"}})
			}
		},
		"too many roots": func(d *DiscoveryPolicy) {
			for i := 0; i <= maxDiscoveryRoots; i++ {
				r := goodDiscovery().Roots[0]
				r.Root = "/srv/r" + strings.Repeat("a", i+1)
				d.Roots = append(d.Roots, r)
			}
		},
		"too many trusted uids": func(d *DiscoveryPolicy) {
			d.Roots[0].TrustedUIDs = nil
			for i := 0; i <= maxDiscoveryUIDs; i++ {
				d.Roots[0].TrustedUIDs = append(d.Roots[0].TrustedUIDs, int64(2000+i))
			}
		},
		"name with newline": func(d *DiscoveryPolicy) { d.Roots[0].Rules[0].Names = []string{"A\nB"} },
	} {
		d := goodDiscovery()
		mod(d)
		if err := policyWith(d).Validate(); err == nil || !strings.Contains(err.Error(), "discovery") {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestDiscoveryNeedsToKnowTheAgents(t *testing.T) {
	p := policyWith(goodDiscovery())
	p.AgentUIDs = nil
	if err := p.Validate(); err == nil {
		t.Fatal("discovery accepted with no agent_uids")
	}
	p = policyWith(goodDiscovery())
	p.UIDShared = true
	if err := p.Validate(); err == nil {
		t.Fatal("discovery accepted on a uid_shared host")
	}
}

func TestParseHostPolicyRefusesUnknownDiscoveryField(t *testing.T) {
	good := `{"version":1,"max_deploys_per_hour":1,"targets":[],"agent_uids":[1],"agent_gids":[],"discovery":{"max_per_hour":1,"roots":[{"root":"/srv/a","trusted_uids":[0],"max_bytes":10,"max_files":1,"rules":[{"glob":"*.env","kind":"env-file","names":["A_KEY"]}]}]}}`
	if _, err := ParseHostPolicy([]byte(good)); err != nil {
		t.Fatalf("good: %v", err)
	}
	bad := strings.Replace(good, `"max_files":1`, `"max_files":1,"follow_symlinks":true`, 1)
	if _, err := ParseHostPolicy([]byte(bad)); err == nil {
		t.Fatal("an unknown discovery field was accepted")
	}
}

func TestDiscoverLimiterCapsPerHour(t *testing.T) {
	l := NewDiscoverLimiter(policyWith(goodDiscovery())) // 4 per hour
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		if err := l.Allow(now); err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
	}
	if err := l.Allow(now.Add(time.Minute)); err == nil {
		t.Fatal("a fifth scan within the hour was allowed")
	}
	if err := l.Allow(now.Add(time.Hour + time.Second)); err != nil {
		t.Fatalf("the cap did not reset after an hour: %v", err)
	}
	if err := NewDiscoverLimiter(policyWith(nil)).Allow(now); err == nil {
		t.Fatal("a host without a discovery section allowed a scan")
	}
}
