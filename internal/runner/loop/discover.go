package loop

import (
	"context"
	"path/filepath"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/runner/discover"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func failDiscover(c runnerproto.ErrorClass) runnerproto.DiscoverResult {
	return runnerproto.DiscoverResult{ErrorClass: c, Findings: []runnerproto.DiscoverFinding{}}
}

// executeDiscover answers a discover job. The host policy decides everything
// about the scan (roots, rules, owners, limits): the job names a store and
// nothing else. Order: policy, rate cap, then the store's fingerprint key,
// then the scan. Any scan failure is the one class discovery_failed with no
// findings, because a read or parse failure proves nothing about absence and
// its detail would leak one bit about a file.
func (r *Runner) executeDiscover(ctx context.Context, j runnerproto.Job) runnerproto.DiscoverResult {
	if err := runnerproto.Check(j, r.Policy); err != nil {
		return discoverClass(runnerproto.ClassOf(err))
	}
	if r.Discover == nil || r.Discover.Allow(r.now()) != nil {
		return failDiscover(runnerproto.ErrClassRateLimited)
	}
	if r.Outbox == nil || r.Delivery == nil {
		return failDiscover(runnerproto.ErrClassInternal)
	}
	env, err := r.Transport.FetchValue(ctx, j.JobID)
	if err != nil {
		return failDiscover(runnerproto.ErrClassInternal)
	}
	key, err := builtin.OpenDiscoverKey(j, r.Delivery, env)
	if err != nil {
		return failDiscover(runnerproto.ErrClassInternal)
	}
	defer key.Wipe()
	var out []runnerproto.DiscoverFinding
	for _, root := range r.Policy.Discovery.Roots {
		found, err := discover.Scan(ctx, scanPolicy(root), key)
		if err != nil {
			return failDiscover(runnerproto.ErrClassDiscoveryFailed)
		}
		for _, f := range found {
			out = append(out, runnerproto.DiscoverFinding{
				Path: filepath.Join(root.Root, f.Path), Name: f.Name, Fingerprint: f.Fingerprint, Len: f.Len,
			})
		}
	}
	if out == nil {
		out = []runnerproto.DiscoverFinding{}
	}
	res := runnerproto.DiscoverResult{OK: true, Findings: out}
	if res.Validate() != nil {
		return failDiscover(runnerproto.ErrClassDiscoveryFailed)
	}
	return res
}

// discoverClass keeps a refusal inside the classes a discover report may carry.
func discoverClass(c runnerproto.ErrorClass) runnerproto.DiscoverResult {
	res := failDiscover(c)
	if res.Validate() != nil {
		return failDiscover(runnerproto.ErrClassPolicyDenied)
	}
	return res
}

func scanPolicy(r runnerproto.DiscoveryRoot) discover.Policy {
	p := discover.Policy{Root: r.Root, MaxBytes: r.MaxBytes, MaxFiles: r.MaxFiles}
	for _, u := range r.TrustedUIDs {
		p.TrustedUIDs = append(p.TrustedUIDs, uint32(u)) //nolint:gosec // G115: range-checked by HostPolicy.Validate
	}
	for _, rule := range r.Rules {
		p.Rules = append(p.Rules, discover.Rule{Glob: rule.Glob, Kind: discover.Kind(rule.Kind), Names: rule.Names})
	}
	return p
}

// isDiscoverPayload reports whether a signed payload is a discover job, so
// its outbox entry is begun with the right kind. It only picks the entry's
// shape; the job is still verified before anything runs.
func isDiscoverPayload(payload []byte) bool {
	j, err := runnerproto.DecodeJob(payload)
	return err == nil && j.Action == runnerproto.ActionDiscover
}
