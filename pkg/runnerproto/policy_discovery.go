package runnerproto

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// DiscoveryPolicy is the host administrator's grant to scan for carriers. It
// exists only in the local host policy: a discover job names a store and
// nothing else, so no path, rule or uid ever comes from the server. Absent
// means discovery is off (policy_denied).
type DiscoveryPolicy struct {
	// Roots are the directories a scan may read, each with its own rules.
	Roots []DiscoveryRoot `json:"roots"`
	// MaxPerHour caps discover jobs this host runs per hour.
	MaxPerHour int `json:"max_per_hour"`
}

// DiscoveryRoot is one scan root: an absolute directory and the finite,
// relative rules beneath it.
type DiscoveryRoot struct {
	Root  string          `json:"root"`
	Rules []DiscoveryRule `json:"rules"`
	// TrustedUIDs are the only owners of files and directories a scan reads.
	// An agent uid is refused here: a file an agent can write is not a place
	// the scanner reads, because the agent could shape what it parses.
	TrustedUIDs []int64 `json:"trusted_uids"`
	MaxBytes    int64   `json:"max_bytes"`
	MaxFiles    int     `json:"max_files"`
}

// DiscoveryRule is one relative glob, its format and the exact variable names
// that may appear in a finding.
type DiscoveryRule struct {
	Glob string `json:"glob"`
	Kind string `json:"kind"`
	// Names are variable names, or exact dotted fields for yaml-scalar. YAML
	// findings keep the whole field so different branches cannot collide.
	Names []string `json:"names"`
}

const (
	maxDiscoveryRoots   = 16
	maxDiscoveryRules   = 64
	maxDiscoveryPerHour = 60
	maxDiscoveryBytes   = 16 << 20
	maxDiscoveryFiles   = 4096
	maxDiscoveryNames   = 256
	maxDiscoveryUIDs    = 32
)

var discoveryKinds = map[string]bool{
	"env-file": true, "launchd-plist": true, "systemd-unit": true, "credential": true, "mcp-config": true, "yaml-scalar": true,
}

func (d DiscoveryPolicy) validate(agentUIDs []int64, uidShared bool) error {
	bad := func(f string, a ...any) error {
		return fmt.Errorf("runnerproto: host policy: discovery: %s", fmt.Sprintf(f, a...))
	}
	// A host that cannot tell agents from the owner cannot keep an agent from
	// shaping a file the scan reads, so it has no discovery.
	if uidShared || len(agentUIDs) == 0 {
		return bad("needs agent_uids and a host where agents do not share the owner uid")
	}
	if len(d.Roots) == 0 || len(d.Roots) > maxDiscoveryRoots {
		return bad("1 to %d roots are required", maxDiscoveryRoots)
	}
	if d.MaxPerHour < 1 || d.MaxPerHour > maxDiscoveryPerHour {
		return bad("max_per_hour must be 1 to %d", maxDiscoveryPerHour)
	}
	seen := map[string]bool{}
	for _, r := range d.Roots {
		if err := ValidatePath(r.Root); err != nil {
			return bad("root %q is not an absolute canonical directory", r.Root)
		}
		if seen[r.Root] {
			return bad("root %q is listed twice", r.Root)
		}
		for other := range seen {
			if strings.HasPrefix(other+"/", r.Root+"/") || strings.HasPrefix(r.Root+"/", other+"/") {
				return bad("root %q overlaps root %q", r.Root, other)
			}
		}
		seen[r.Root] = true
		if len(r.TrustedUIDs) == 0 || len(r.TrustedUIDs) > maxDiscoveryUIDs {
			return bad("root %q needs 1 to %d trusted_uids", r.Root, maxDiscoveryUIDs)
		}
		for _, u := range r.TrustedUIDs {
			if u < 0 || u > 1<<31-1 {
				return bad("trusted uid %d out of range", u)
			}
			if slices.Contains(agentUIDs, u) {
				return bad("trusted uid %d is an agent uid", u)
			}
		}
		if r.MaxBytes < 1 || r.MaxBytes > maxDiscoveryBytes || r.MaxFiles < 1 || r.MaxFiles > maxDiscoveryFiles {
			return bad("root %q needs positive max_bytes and max_files within the caps", r.Root)
		}
		if len(r.Rules) == 0 || len(r.Rules) > maxDiscoveryRules {
			return bad("root %q needs 1 to %d rules", r.Root, maxDiscoveryRules)
		}
		for _, rule := range r.Rules {
			if !discoveryKinds[rule.Kind] {
				return bad("unknown kind %q", rule.Kind)
			}
			if !safeDiscoveryGlob(rule.Glob) || len(rule.Names) == 0 || len(rule.Names) > maxDiscoveryNames {
				return bad("a rule needs a relative finite glob and 1 to %d names", maxDiscoveryNames)
			}
			if rule.Kind == "credential" && len(rule.Names) != 1 {
				return bad("a credential rule names exactly one variable")
			}
			names := map[string]bool{}
			for _, n := range rule.Names {
				valid := envFieldRe.MatchString(n)
				if rule.Kind == string(TargetYAMLScalar) {
					valid = len(n) <= 256 && keyFieldRe.MatchString(n)
				}
				if !valid || names[n] {
					return bad("name %q is malformed or repeated", n)
				}
				names[n] = true
			}
		}
	}
	return nil
}

// ErrDiscoveryRate is returned when the hourly discover cap is spent.
var ErrDiscoveryRate = errors.New("runnerproto: discovery rate limit")

// DiscoverLimiter caps discover jobs per hour. It is separate from Limiter:
// a scan spends no deploy budget and a deploy spends no scan budget.
type DiscoverLimiter struct {
	mu    sync.Mutex
	max   int
	times []time.Time
}

// NewDiscoverLimiter returns a limiter for p; with no discovery section it
// allows nothing.
func NewDiscoverLimiter(p HostPolicy) *DiscoverLimiter {
	l := &DiscoverLimiter{}
	if p.Discovery != nil {
		l.max = p.Discovery.MaxPerHour
	}
	return l
}

// Allow records a scan at now and reports whether it is within the cap.
func (l *DiscoverLimiter) Allow(now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := l.times[:0]
	for _, t := range l.times {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	l.times = keep
	if len(l.times) >= l.max {
		return ErrDiscoveryRate
	}
	l.times = append(l.times, now)
	return nil
}

// safeDiscoveryGlob mirrors what the scanner accepts: relative, at most 16
// segments, no "..", no recursive "**", no "~", a valid filepath.Match pattern.
func safeDiscoveryGlob(g string) bool {
	if g == "" || strings.HasPrefix(g, "/") || strings.Contains(g, "**") || strings.Contains(g, "~") || strings.ContainsRune(g, 0) {
		return false
	}
	parts := strings.Split(g, "/")
	if len(parts) > 16 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	_, err := path.Match(g, "")
	return err == nil
}
