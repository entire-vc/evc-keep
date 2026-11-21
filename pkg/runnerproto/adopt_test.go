package runnerproto

import (
	"bytes"
	"testing"
	"time"
)

func adoptJob(t *testing.T) Job {
	j := deployJob(t)
	j.Action = ActionAdopt
	j.Target = Target{Kind: TargetYAMLScalar, Path: "/etc/keep/app/config.yaml", Field: "service.API_KEY", Mode: 0o600}
	return j
}

func TestAdoptIsSeparateReadOnlySignedAction(t *testing.T) {
	j := adoptJob(t)
	if j.Validate() != nil || j.NeedsValue() || !j.NeedsFingerprintKey() {
		t.Fatal("adoption must receive a key alone")
	}
	b, err := EncodeJob(j)
	if err != nil {
		t.Fatal("encode adoption")
	}
	got, err := DecodeJob(b)
	if err != nil || got.Action != ActionAdopt || got.Target != j.Target {
		t.Fatal("adoption lost its action or exact destination on the wire")
	}
	for name, change := range map[string]func(*Job){
		"writer":     func(j *Job) { j.Action = ActionDeploy },
		"other-kind": func(j *Job) { j.Target.Kind = TargetEnvFile },
		"consumer":   func(j *Job) { j.Target.Consumer = "systemd:app.service" },
		"unit":       func(j *Job) { j.Target.Unit = "app.service" },
		"exec":       func(j *Job) { j.Exec = execJob(t).Exec },
	} {
		t.Run(name, func(t *testing.T) {
			other := j
			change(&other)
			if other.Validate() == nil {
				t.Fatal("adoption accepted a non-read-only operation")
			}
		})
	}
	for _, k := range TargetKinds {
		if k.SupportsAction(ActionDeploy) != (k != TargetYAMLScalar) || !k.SupportsAction(ActionVerify) || k.SupportsAction(ActionAdopt) != (k == TargetYAMLScalar) {
			t.Fatal("target capabilities differ from the supported operations")
		}
	}
}

func TestAdoptRequiresExactHostGrantInAdditionToReadRule(t *testing.T) {
	j := adoptJob(t)
	p := testPolicy()
	p.Targets = []TargetRule{{Kind: TargetYAMLScalar, PathPrefixes: []string{"/etc/keep"}, Fields: []string{j.Target.Field, "other.API_KEY"}}}
	if Check(j, p) == nil {
		t.Fatal("read rule implicitly granted adoption")
	}
	p.AdoptionTargets = []AdoptionTarget{{Path: j.Target.Path, Field: j.Target.Field}}
	if err := Check(j, p); err != nil {
		t.Fatal("explicit exact adoption grant refused")
	}
	for name, change := range map[string]func(*Job, *HostPolicy){
		"neighbor-path":  func(j *Job, _ *HostPolicy) { j.Target.Path += ".other" },
		"neighbor-field": func(j *Job, _ *HostPolicy) { j.Target.Field = "other.API_KEY" },
		"no-read-rule":   func(_ *Job, p *HostPolicy) { p.Targets = nil },
		"shared-prod":    func(_ *Job, p *HostPolicy) { p.UIDShared = true },
		"agent-owner":    func(j *Job, p *HostPolicy) { j.Target.UID = p.AgentUIDs[0] },
	} {
		t.Run(name, func(t *testing.T) {
			other, policy := j, p
			change(&other, &policy)
			if Check(other, policy) == nil {
				t.Fatal("adoption widened the host grant")
			}
		})
	}
	for _, targets := range [][]AdoptionTarget{
		{{Path: "/etc/keep/../other", Field: j.Target.Field}},
		{{Path: j.Target.Path, Field: "service.*"}},
		{p.AdoptionTargets[0], p.AdoptionTargets[0]},
		make([]AdoptionTarget, 129),
	} {
		other := p
		other.AdoptionTargets = targets
		if other.Validate() == nil {
			t.Fatal("ambiguous or unbounded adoption grants accepted")
		}
	}
}

func TestAdoptKeyInfoBindsEntireJobAndOwnDomain(t *testing.T) {
	j := adoptJob(t)
	info := AdoptKeyInfo(j)
	if !bytes.HasPrefix(info, []byte("keep/fingerprint-key/adopt/v1\x00")) {
		t.Fatal("adoption key domain changed")
	}
	for _, other := range [][]byte{Info(j), FingerprintKeyInfo(j), VerifyKeyInfo(j), DiscoverKeyInfo(j)} {
		if bytes.HasPrefix(info, other) || bytes.HasPrefix(other, info) {
			t.Fatal("adoption domain overlaps another key/value domain")
		}
	}
	for name, change := range map[string]func(*Job){
		"org":     func(j *Job) { j.OrgID += "-other" },
		"runner":  func(j *Job) { j.RunnerID += "-other" },
		"secret":  func(j *Job) { j.Secret.Name += "-other" },
		"store":   func(j *Job) { j.Secret.StoreID += "-other" },
		"version": func(j *Job) { j.ExpectedVersion += "-other" },
		"path":    func(j *Job) { j.Target.Path += ".other" },
		"field":   func(j *Job) { j.Target.Field += "_OTHER" },
		"job":     func(j *Job) { j.JobID = newJobID(t) },
		"nonce":   func(j *Job) { j.Nonce = bytes.Repeat([]byte{9}, NonceSize) },
		"expiry":  func(j *Job) { j.NotAfter = j.NotAfter.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			other := j
			change(&other)
			if bytes.Equal(info, AdoptKeyInfo(other)) {
				t.Fatal("adoption envelope not bound to complete job")
			}
		})
	}
}
