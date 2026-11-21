package rotation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	kstore "github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	prot "github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/google/uuid"
)

const fpOld = "kfp1:k1:ponmlkjihgfedcba"

// rbFakes is a DualKey provider seen from the engine: it records every layout
// and read-back with the version asked for, whether the call was part of a
// rollback, and what the new key went through.
type rbFakes struct {
	*fakes
	lmu         sync.Mutex
	log         []string
	cannot      bool              // CanRollback false: forward-only or adopted
	canErrs     int               // CanRollback fails this many times before it answers
	rbDeployErr map[string]error  // rollback layout refused per carrier
	rbVerifyFP  map[string]string // fingerprint a carrier reports after the rollback layout
	rbUnhealthy map[string]bool
	rollbackErr error
	keyActive   bool
	current     string
	rbCalls     int
}

func newRB(n int) *rbFakes {
	return &rbFakes{fakes: newFakes(n), rbDeployErr: map[string]error{}, rbVerifyFP: map[string]string{},
		rbUnhealthy: map[string]bool{}, keyActive: true, current: "2"}
}

func (r *rbFakes) add(s string) {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	r.log = append(r.log, s)
}

func (r *rbFakes) count(prefix string) int {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	n := 0
	for _, s := range r.log {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

func (r *rbFakes) exact(s string) int {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	n := 0
	for _, have := range r.log {
		if have == s {
			n++
		}
	}
	return n
}

// putBackBeforeRead: the run's one verification is a snapshot of every carrier,
// so no carrier may be read before the last one is put back.
func (r *rbFakes) putBackBeforeRead() bool {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	lastDeploy, firstVerify := -1, len(r.log)
	for i, s := range r.log {
		if strings.HasPrefix(s, "rollback-deploy") {
			lastDeploy = i
		}
		if strings.HasPrefix(s, "rollback-verify") && i < firstVerify {
			firstVerify = i
		}
	}
	return lastDeploy < firstVerify
}

func (r *rbFakes) Deploy(ctx context.Context, ref Ref, id uuid.UUID, c Carrier, v string) error {
	if IsRollback(ctx) {
		r.add(fmt.Sprintf("rollback-deploy %s %s", v, c.ID))
		return r.rbDeployErr[c.ID]
	}
	r.add(fmt.Sprintf("deploy %s %s", v, c.ID))
	return r.fakes.Deploy(ctx, ref, id, c, v)
}

func (r *rbFakes) Verify(ctx context.Context, ref Ref, c Carrier, v string) (Report, error) {
	if IsRollback(ctx) {
		r.add(fmt.Sprintf("rollback-verify %s %s", v, c.ID))
		fp := fpOld
		if o, ok := r.rbVerifyFP[c.ID]; ok {
			fp = o
		}
		return Report{Fingerprint: fp, Healthy: !r.rbUnhealthy[c.ID]}, nil
	}
	return r.fakes.Verify(ctx, ref, c, v)
}

func (r *rbFakes) CanRollback(context.Context, Ref, uuid.UUID) (bool, error) {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	if r.canErrs != 0 {
		if r.canErrs > 0 {
			r.canErrs--
		}
		return false, errors.New("ledger down")
	}
	return !r.cannot, nil
}

func (r *rbFakes) RollbackNew(_ context.Context, _ Ref, _ uuid.UUID) error {
	r.add("revoke-new")
	r.lmu.Lock()
	defer r.lmu.Unlock()
	r.rbCalls++
	if r.rollbackErr != nil {
		return r.rollbackErr
	}
	r.keyActive, r.current = false, "1"
	return nil
}

func (r *rbFakes) deps() Deps {
	d := r.fakes.deps()
	d.Versions, d.Deployer, d.Verifier = r, r, r
	return d
}

// (a) the third of five carriers refuses: the first two go back on the old
// version and are read back, then the new key is ended and the old version is
// current again; the carriers after the failure were never touched.
func TestRollbackPutsCarriersBackThenEndsTheNewKey(t *testing.T) {
	x, f := newFx(t), newRB(5)
	f.deployErr[cid(3)] = errors.New("boom")
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{Concurrency: 1})
	if !errors.Is(err, ErrFailed) || res.State != StateFailed || res.Class != ClassDeployFailed {
		t.Fatalf("want failed/deploy_failed, got %+v %v", res, err)
	}
	for _, n := range []int{1, 2} {
		if f.exact(fmt.Sprintf("rollback-deploy 1 %s", cid(n))) != 1 || f.exact(fmt.Sprintf("rollback-verify 1 %s", cid(n))) != 1 {
			t.Fatalf("carrier %d not put back on the old version and read back: %v", n, f.log)
		}
	}
	if f.count("rollback-deploy") != 5 { // 1, 2, the refused 3 and the untouched 4, 5: best effort
		t.Fatalf("rollback layouts: %v", f.log)
	}
	if !f.putBackBeforeRead() {
		t.Fatalf("a carrier was read before every carrier was put back: %v", f.log)
	}
	for _, n := range []int{4, 5} {
		// never delivered the new version: put back best effort, never read, never required
		if f.exact(fmt.Sprintf("rollback-deploy 1 %s", cid(n))) != 1 || f.count(fmt.Sprintf("rollback-verify 1 %s", cid(n))) != 0 || f.count(fmt.Sprintf("deploy 2 %s", cid(n))) != 0 {
			t.Fatalf("carrier %d was never touched: put back best effort only: %v", n, f.log)
		}
	}
	if f.rbCalls != 1 || f.keyActive || f.current != "1" || f.revokes != 0 {
		t.Fatalf("new key: calls=%d active=%v current=%s old revokes=%d", f.rbCalls, f.keyActive, f.current, f.revokes)
	}
	// the key is ended after every carrier that took the new version is back
	last := -1
	for i, s := range f.log {
		if strings.HasPrefix(s, "rollback-verify") {
			last = i
		}
		if s == "revoke-new" && last < 0 {
			t.Fatalf("the key was ended before any carrier was read back: %v", f.log)
		}
	}
	if len(f.incidents) != 1 || f.incidents[0].Class != ClassDeployFailed {
		t.Fatalf("incident: %+v", f.incidents)
	}
}

// A verification failure is rolled back as well, on all five carriers.
func TestRollbackAfterVerifyFailure(t *testing.T) {
	for name, set := range map[string]func(*rbFakes){
		"unhealthy":   func(f *rbFakes) { f.unhealthy[cid(2)] = true },
		"fingerprint": func(f *rbFakes) { f.verifyFP[cid(2)] = fpBad },
		"verify":      func(f *rbFakes) { f.verifyErr[cid(2)] = errors.New("read") },
	} {
		t.Run(name, func(t *testing.T) {
			x, f := newFx(t), newRB(5)
			set(f)
			res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
			if !errors.Is(err, ErrFailed) || res.State != StateFailed || res.Class == ClassNone {
				t.Fatalf("got %+v %v", res, err)
			}
			if f.count("rollback-deploy 1") != 5 || f.count("rollback-verify 1") != 5 || f.rbCalls != 1 || f.keyActive {
				t.Fatalf("rollback: %v active=%v", f.log, f.keyActive)
			}
		})
	}
}

// (b) a carrier cannot be confirmed back on the old version: the new key stays,
// an incident names the carrier, the run is failed with its own class.
func TestRollbackUnconfirmedLeavesTheNewKey(t *testing.T) {
	for name, set := range map[string]func(*rbFakes){
		"deploy refused":    func(f *rbFakes) { f.rbDeployErr[cid(2)] = errors.New("down") },
		"still new key":     func(f *rbFakes) { f.rbVerifyFP[cid(2)] = fpNew },
		"unhealthy":         func(f *rbFakes) { f.rbUnhealthy[cid(2)] = true },
		"unreadable":        func(f *rbFakes) { f.rbVerifyFP[cid(2)] = "garbage" },
		"empty fingerprint": func(f *rbFakes) { f.rbVerifyFP[cid(2)] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			x, f := newFx(t), newRB(3)
			f.deployErr[cid(3)] = errors.New("boom")
			set(f)
			res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{Concurrency: 1})
			if !errors.Is(err, ErrFailed) || res.State != StateFailed || res.Class != ClassDeployFailed {
				t.Fatalf("got %+v %v", res, err)
			}
			if f.rbCalls != 0 || !f.keyActive || f.revokes != 0 {
				t.Fatalf("the new key was ended without every carrier confirmed: %v", f.log)
			}
			if len(f.incidents) != 1 || f.incidents[0].Class != ClassRollbackUnconfirmed || strings.Join(f.incidents[0].Carriers, ",") != cid(2) || f.incidentCalls != 1 {
				t.Fatalf("incident: %+v calls=%d", f.incidents, f.incidentCalls)
			}
			var opened bool
			if err := x.pool.QueryRow(x.ctx, `SELECT incident_opened FROM rotation_runs WHERE id=$1`, res.RunID).Scan(&opened); err != nil || !opened {
				t.Fatalf("incident not recorded on the run: %v %v", opened, err)
			}
		})
	}
}

// One carrier that cannot be confirmed does not stop the read of the others: the
// incident names only the carrier that failed.
func TestRollbackIncidentNamesOnlyTheCarriersThatFailed(t *testing.T) {
	x, f := newFx(t), newRB(4)
	f.deployErr[cid(4)] = errors.New("boom")
	f.rbVerifyFP[cid(1)] = fpNew
	if _, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{Concurrency: 1}); !errors.Is(err, ErrFailed) {
		t.Fatalf("got %v", err)
	}
	if f.count("rollback-verify") != 3 || len(f.incidents) != 1 || strings.Join(f.incidents[0].Carriers, ",") != cid(1) {
		t.Fatalf("incident %+v log %v", f.incidents, f.log)
	}
}

// The provider could not end the key, or disable the version: an incident, and
// the run is failed.
func TestRollbackNewKeyNotEndedIsAnIncident(t *testing.T) {
	x, f := newFx(t), newRB(3)
	f.unhealthy[cid(2)] = true
	f.rollbackErr = errors.New("provider down")
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
	if !errors.Is(err, ErrFailed) || res.State != StateFailed || res.Class != ClassUnhealthy {
		t.Fatalf("got %+v %v", res, err)
	}
	if len(f.incidents) != 1 || f.incidents[0].Class != ClassRollbackUnconfirmed || len(f.incidents[0].Carriers) != 0 {
		t.Fatalf("incident: %+v", f.incidents)
	}
}

// (c) the process dies in rolling_back: Resume finishes the same rollback, once
// the key is ended and no carrier is left on the new version.
func TestRollbackResumesAfterACrash(t *testing.T) {
	x, f := newFx(t), newRB(4)
	f.deployErr[cid(4)] = errors.New("boom")
	id := uuid.New()
	dying := New(x.pool, f.deps())
	dying.afterState = func(s State) error {
		if s == StateRollingBack {
			return errors.New("killed")
		}
		return nil
	}
	if _, err := dying.Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1}); err == nil {
		t.Fatal("expected the simulated kill")
	}
	var st string
	if err := x.pool.QueryRow(x.ctx, `SELECT state FROM rotation_runs WHERE id=$1`, id).Scan(&st); err != nil || st != string(StateRollingBack) {
		t.Fatalf("state after the kill: %q %v", st, err)
	}
	if f.count("rollback-") != 0 || f.rbCalls != 0 {
		t.Fatalf("nothing was undone before the kill: %v", f.log)
	}
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1})
	if !errors.Is(err, ErrFailed) || res.State != StateFailed || res.Class != ClassDeployFailed {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if f.count("rollback-deploy 1") != 4 || f.count("rollback-verify 1") != 3 || f.rbCalls != 1 || f.keyActive {
		t.Fatalf("after resume: %v active=%v", f.log, f.keyActive)
	}
	// a second call replays the finished run and undoes nothing again
	if _, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{RunID: id}); !errors.Is(err, ErrFailed) || f.rbCalls != 1 {
		t.Fatalf("replay: %v calls=%d", err, f.rbCalls)
	}
}

// Where there is nothing to undo the run ends as before: forward-only and first
// rotation (no old version), a failure that touched no carrier, a run whose key
// is not its own.
func TestRollbackOnlyWhereItAppliesKeepsTheOldBehaviour(t *testing.T) {
	cases := map[string]func(*rbFakes){
		"forward-only": func(f *rbFakes) { f.cannot = true },
		"no carriers":  func(f *rbFakes) { f.carriers = nil },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			x, f := newFx(t), newRB(3)
			f.deployErr[cid(2)] = errors.New("boom")
			set(f)
			res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{Concurrency: 1})
			if !errors.Is(err, ErrFailed) || res.State != StateFailed {
				t.Fatalf("got %+v %v", res, err)
			}
			// A definite no from the provider ends the run with the class of
			// the failure, as before rollback existed.
			if name == "forward-only" && res.Class != ClassDeployFailed {
				t.Fatalf("class %q, want %q", res.Class, ClassDeployFailed)
			}
			if f.count("rollback-") != 0 || f.rbCalls != 0 {
				t.Fatalf("rolled back where it does not apply: %v", f.log)
			}
		})
	}
	t.Run("first rotation", func(t *testing.T) {
		x, f := newFx(t), newRB(3)
		f.deployErr[cid(2)] = errors.New("boom")
		d := f.deps()
		d.Versions = noOldVersion{f}
		res, err := New(x.pool, d).Rotate(x.ctx, x.ref, Options{Concurrency: 1})
		if !errors.Is(err, ErrFailed) || res.State != StateFailed || f.count("rollback-") != 0 || f.rbCalls != 0 {
			t.Fatalf("got %+v %v %v", res, err, f.log)
		}
	})
	t.Run("plain fakes are not a Rollbacker", func(t *testing.T) {
		x, f := newFx(t), newFakes(3)
		f.deployErr[cid(2)] = errors.New("boom")
		if res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{Concurrency: 1}); !errors.Is(err, ErrFailed) || res.State != StateFailed {
			t.Fatalf("got %+v %v", res, err)
		}
	})
}

type noOldVersion struct{ *rbFakes }

func (n noOldVersion) Prepare(context.Context, Ref, uuid.UUID) (Version, error) {
	return Version{Old: "", New: "2", Fingerprint: fpNew}, nil
}

// A failure that is not a layout or verification failure is not rolled back:
// a newer version replaced the run.
func TestRollbackSkipsASupersededRun(t *testing.T) {
	x, f := newFx(t), newRB(3)
	f.unhealthy[cid(2)] = true
	d := f.deps()
	d.Versions = supersedingRB{f}
	res, err := New(x.pool, d).Rotate(x.ctx, x.ref, Options{})
	if !errors.Is(err, ErrFailed) || res.Class != ClassSuperseded || f.count("rollback-") != 0 || f.rbCalls != 0 {
		t.Fatalf("got %+v %v %v", res, err, f.log)
	}
}

type supersedingRB struct{ *rbFakes }

func (supersedingRB) NewerSealed(context.Context, Ref, string) (bool, error) { return true, nil }

// Leak test: a value in a collaborator's error must reach no result, incident
// or row of the rollback path.
func TestRollbackNeverCarriesAValue(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	for name, set := range map[string]func(*rbFakes){
		"rollback deploy": func(f *rbFakes) { f.rbDeployErr[cid(1)] = errors.New("put back " + v) },
		"rollback key":    func(f *rbFakes) { f.rollbackErr = errors.New("revoke " + v) },
		"rollback fp":     func(f *rbFakes) { f.rbVerifyFP[cid(1)] = v },
		"incident sink":   func(f *rbFakes) { f.rbDeployErr[cid(1)] = errors.New("x"); f.incErr = errors.New("journal " + v) },
	} {
		t.Run(name, func(t *testing.T) {
			x, f := newFx(t), newRB(3)
			f.unhealthy[cid(2)] = true
			set(f)
			res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{})
			var dump strings.Builder
			fmt.Fprintf(&dump, "%+v %#v %v %+v", res, res, err, f.incidents)
			for _, q := range []string{`SELECT coalesce(string_agg(row_to_json(r)::text, ' '), '') FROM rotation_runs r`,
				`SELECT coalesce(string_agg(row_to_json(s)::text, ' '), '') FROM rotation_steps s`} {
				var s string
				if err := x.pool.QueryRow(x.ctx, q).Scan(&s); err != nil {
					t.Fatal(err)
				}
				dump.WriteString(s)
			}
			if f.count("rollback-") == 0 {
				t.Fatal("the rollback did not run; the test proves nothing")
			}
			if c.In(dump.String()) {
				t.Fatalf("canary reached the result, an incident, an error or a row (%d bytes inspected)", dump.Len())
			}
		})
	}
}

// The real provider adapter: after a failed second run the carriers are back on
// the old version, the NEW key is ended (never the old one), the new version is
// disabled and the old one is current again.
func TestProviderFailedRunEndsOnlyTheNewKey(t *testing.T) {
	p := newProvFx(t, true, 3)
	first := p.firstRun(t)
	oldKey := p.rp.lastID
	p.col.unhealthy[cid(2)] = true
	r, err := p.rotate()
	if !errors.Is(err, ErrFailed) || r.State != StateFailed || r.Class != ClassUnhealthy {
		t.Fatalf("got %+v %v", r, err)
	}
	newKey := p.rp.lastID
	if newKey == oldKey || p.ev.count("rollback-deploy") != 3 || p.ev.count("rollback-verify") != 3 {
		t.Fatalf("carriers not put back: %v", p.ev.all())
	}
	if p.ev.exact("revoke "+newKey) != 1 || p.ev.count("revoke") != 1 {
		t.Fatalf("want exactly one revoke, of the new key: %v", p.ev.all())
	}
	if p.rp.active[newKey] || !p.rp.active[oldKey] {
		t.Fatalf("new key active=%v old key active=%v", p.rp.active[newKey], p.rp.active[oldKey])
	}
	if p.ev.last("rollback-verify") > p.ev.first("revoke") || p.ev.first("revoke") > p.ev.first("disable") {
		t.Fatalf("order: %v", p.ev.all())
	}
	if p.ev.exact("disable "+r.NewVersion) != 1 || p.ev.count("disable") != 1 {
		t.Fatalf("only the new version is disabled: %v", p.ev.all())
	}
	if m, err := p.mem.Version(p.ctx, provider.Ref{Path: provPath}); err != nil || m.Version != first.NewVersion {
		t.Fatalf("current version %+v %v, want %s", m, err, first.NewVersion)
	}
}

// A carrier that does not come back: the new key stays active.
func TestProviderUnconfirmedRollbackKeepsTheNewKeyActive(t *testing.T) {
	p := newProvFx(t, true, 3)
	p.firstRun(t)
	p.col.unhealthy[cid(2)] = true
	p.col.rbBad[cid(1)] = true
	p.col.incidents = nil
	r, err := p.rotate()
	if !errors.Is(err, ErrFailed) || r.State != StateFailed || r.Class != ClassUnhealthy {
		t.Fatalf("got %+v %v", r, err)
	}
	if p.ev.count("revoke") != 0 || p.ev.count("disable") != 0 || !p.rp.active[p.rp.lastID] {
		t.Fatalf("the new key was touched: %v", p.ev.all())
	}
	if len(p.col.incidents) != 1 || p.col.incidents[0].Class != ClassRollbackUnconfirmed || strings.Join(p.col.incidents[0].Carriers, ",") != cid(1) {
		t.Fatalf("incident: %+v", p.col.incidents)
	}
}

// The provider ends the key but still reports it active: not confirmed, so the
// new version is not disabled and the run says so.
func TestProviderRollbackNeedsCheckToConfirm(t *testing.T) {
	for name, set := range map[string]func(*provFx){
		"still active":  func(p *provFx) { p.rp.stillOn = true },
		"check fails":   func(p *provFx) { p.rp.checkErr = errors.New("down") },
		"revoke fails":  func(p *provFx) { p.rp.revokeErr = errors.New("down") },
		"disable fails": func(p *provFx) { p.store.disErr = errors.New("down") },
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvFx(t, true, 2)
			p.firstRun(t)
			p.col.unhealthy[cid(2)] = true
			set(p)
			p.col.incidents = nil
			r, err := p.rotate()
			if !errors.Is(err, ErrFailed) || r.State != StateFailed {
				t.Fatalf("got %+v %v", r, err)
			}
			if len(p.col.incidents) != 1 || p.col.incidents[0].Class != ClassRollbackUnconfirmed {
				t.Fatalf("incident: %+v", p.col.incidents)
			}
			if name != "disable fails" && p.ev.count("disable") != 0 {
				t.Fatalf("the version was disabled before the key was confirmed ended: %v", p.ev.all())
			}
		})
	}
}

// CanRollback is false where there is no key of the run's own to end.
func TestProviderCanRollbackOnlyForAnIssuedKeyOfADualKeyProvider(t *testing.T) {
	p := newProvFx(t, true, 1)
	run := uuid.New()
	vv := NewProviderVersions(p.deps)
	p.store.verErr = provider.ErrNotFound // nothing sealed yet: no old version
	if _, err := vv.Prepare(p.ctx, p.ref, run); err != nil {
		t.Fatal(err)
	}
	if ok, err := vv.CanRollback(p.ctx, p.ref, run); err != nil || ok {
		t.Fatalf("first rotation has no old version to go back to: %v %v", ok, err)
	}
	p.store.verErr = nil
	p.firstRun(t)
	run = uuid.New()
	if _, err := vv.Prepare(p.ctx, p.ref, run); err != nil {
		t.Fatal(err)
	}
	if ok, err := vv.CanRollback(p.ctx, p.ref, run); err != nil || !ok {
		t.Fatalf("issued key of a DualKey provider: %v %v", ok, err)
	}
	if ok, _ := vv.CanRollback(p.ctx, Ref{OrgID: p.ref.OrgID, SecretID: uuid.New()}, run); ok {
		t.Fatal("another secret rolled the run back")
	}
	if ok, _ := vv.CanRollback(p.ctx, p.ref, uuid.New()); ok {
		t.Fatal("an unknown run can roll back")
	}
	// adopted: a human entered the value, no key was issued
	adopt := uuid.New()
	w, err := vv.Adopt(p.ctx, p.ref, adopt, Version{Old: "2", New: "9", Fingerprint: fpNew})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := p.pool.Begin(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := w(p.ctx, tx); err != nil || tx.Commit(p.ctx) != nil {
		t.Fatalf("adopt write: %v", err)
	}
	p.ev.reset()
	if ok, err := vv.CanRollback(p.ctx, p.ref, adopt); err != nil || ok {
		t.Fatalf("a version a human entered has no key to end: %v %v", ok, err)
	}
	if err := vv.RollbackNew(p.ctx, p.ref, adopt); !errors.Is(err, ErrRevoke) || p.ev.count("revoke") != 0 {
		t.Fatalf("RollbackNew on an adopted run: %v %v", err, p.ev.all())
	}
	// forward-only
	q := newProvFx(t, false, 1)
	fr := uuid.New()
	fv := NewProviderVersions(q.deps)
	if _, err := fv.Prepare(q.ctx, q.ref, fr); err != nil {
		t.Fatal(err)
	}
	if ok, _ := fv.CanRollback(q.ctx, q.ref, fr); ok {
		t.Fatal("a forward-only provider has no way back")
	}
}

// Issue may hand the original key back on a resume: ending it would end the key
// the carriers were just put back on.
func TestProviderRollbackNeverEndsTheOriginalKey(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.firstRun(t)
	orig := uuid.NewString()
	p.rp.origin, p.rp.nextID = orig, orig
	p.rp.mu.Lock()
	p.rp.active[orig] = true
	p.rp.mu.Unlock()
	run := uuid.New()
	vv := NewProviderVersions(p.deps)
	if _, err := vv.Prepare(p.ctx, p.ref, run); err != nil {
		t.Fatal(err)
	}
	p.ev.reset()
	if err := vv.RollbackNew(p.ctx, p.ref, run); !errors.Is(err, ErrRevoke) || p.ev.count("revoke") != 0 || p.ev.count("disable") != 0 {
		t.Fatalf("got %v %v", err, p.ev.all())
	}
}

// The original key is unknown and the provider hands back the key a run recorded
// for the old version: ending it would end the key the carriers are back on.
func TestProviderRollbackNeverEndsTheKeyOfTheOldVersion(t *testing.T) {
	p := newProvFx(t, true, 1)
	p.firstRun(t)
	if r, err := p.rotate(); err != nil || r.State != StateDone { // a run that recorded the key of the current version
		t.Fatalf("setup rotation: %+v %v", r, err)
	}
	oldKey, _, err := p.deps.Ledger.keyOf(p.ctx, p.ref, "3")
	if err != nil || oldKey == "" {
		t.Fatalf("the setup run left no key for version 3 (%q, %v): the test proves nothing", oldKey, err)
	}
	p.rp.origin, p.rp.nextID = "", oldKey
	p.rp.mu.Lock()
	p.rp.active[oldKey] = true
	p.rp.mu.Unlock()
	run := uuid.New()
	vv := NewProviderVersions(p.deps)
	if _, err := vv.Prepare(p.ctx, p.ref, run); err != nil {
		t.Fatal(err)
	}
	p.ev.reset()
	if err := vv.RollbackNew(p.ctx, p.ref, run); !errors.Is(err, ErrRevoke) || p.ev.count("revoke") != 0 || p.ev.count("disable") != 0 {
		t.Fatalf("got %v %v", err, p.ev.all())
	}
}

// Leak test at the provider seam: the issued value never reaches the rollback's
// results, incidents or errors.
func TestProviderRollbackNeverCarriesTheIssuedValue(t *testing.T) {
	c := canary.New()
	p := newProvFx(t, true, 2)
	p.firstRun(t)
	p.rp.value = c.Value(7)
	p.col.unhealthy[cid(2)] = true
	p.rp.revokeErr = errors.New("provider refused " + c.Value(7))
	r, err := p.rotate()
	var dump strings.Builder
	fmt.Fprintf(&dump, "%+v %v %+v %v", r, err, p.col.incidents, p.ev.all())
	var rows string
	if qerr := p.pool.QueryRow(p.ctx, `SELECT coalesce(string_agg(row_to_json(r)::text, ' '), '') FROM rotation_runs r`).Scan(&rows); qerr != nil {
		t.Fatal(qerr)
	}
	dump.WriteString(rows)
	if p.ev.count("rollback-deploy") == 0 || p.rp.n == 0 {
		t.Fatal("the rollback did not run; the test proves nothing")
	}
	if c.In(dump.String()) {
		t.Fatalf("the issued value reached a result, an incident, a log or a row (%d bytes inspected)", dump.Len())
	}
}

var _ prot.RotationProvider = (*stubProvider)(nil)

// The migration that adds rolling_back goes down with a run caught in it, and
// up again.
func TestRollingBackMigrationDownAndUp(t *testing.T) {
	x := newFx(t)
	run := uuid.New()
	if _, err := x.pool.Exec(x.ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state, error_class) VALUES ($1,$2,$3,'rolling_back','deploy_failed')`, run, x.ref.OrgID, x.ref.SecretID); err != nil {
		t.Fatal("rolling_back is not an accepted state")
	}
	mdb, err := kstore.OpenMigrationDB(x.ctx, x.pool.Config().ConnString())
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	prov, err := kstore.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err := prov.DownTo(x.ctx, 51); err != nil {
		t.Fatalf("downgrade with a run in rolling_back: %v", err)
	}
	var st, cl string
	if err := x.pool.QueryRow(x.ctx, `SELECT state, error_class FROM rotation_runs WHERE id=$1`, run).Scan(&st, &cl); err != nil || st != "failed" || cl != "deploy_failed" {
		t.Fatalf("run after downgrade: %q %q %v", st, cl, err)
	}
	var cols int
	if err := x.pool.QueryRow(x.ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='rotation_keys' AND column_name='adopted'`).Scan(&cols); err != nil || cols != 0 {
		t.Fatal("downgrade left the adopted column")
	}
	if _, err := x.pool.Exec(x.ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state) VALUES ($1,$2,$3,'rolling_back')`, uuid.New(), x.ref.OrgID, uuid.New()); err == nil {
		t.Fatal("the downgraded schema still accepts rolling_back")
	}
	if _, err := prov.Up(x.ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if _, err := x.pool.Exec(x.ctx, `INSERT INTO rotation_runs(id, org_id, secret_id, state) VALUES ($1,$2,$3,'rolling_back')`, uuid.New(), x.ref.OrgID, uuid.New()); err != nil {
		t.Fatal("rolling_back is not accepted after up")
	}
}

// CanRollback cannot answer (the ledger or the provider is down for a moment):
// the run is not ended as plain failed with the key alive. It stays in
// rolling_back, and the resume that finds the ledger back puts the carriers
// back and ends the key.
func TestRollbackCapabilityErrorKeepsTheRunRollingBack(t *testing.T) {
	x, f := newFx(t), newRB(3)
	f.deployErr[cid(3)] = errors.New("boom")
	f.canErrs = 1
	id := uuid.New()
	if _, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1}); err == nil || errors.Is(err, ErrFailed) {
		t.Fatalf("a capability error must not end the run failed: %v", err)
	}
	var st string
	if err := x.pool.QueryRow(x.ctx, `SELECT state FROM rotation_runs WHERE id=$1`, id).Scan(&st); err != nil || st != string(StateRollingBack) {
		t.Fatalf("state after the error: %q %v", st, err)
	}
	if !f.keyActive || f.rbCalls != 0 {
		t.Fatalf("the key was touched before the capability was known: %v", f.log)
	}
	res, err := New(x.pool, f.deps()).Rotate(x.ctx, x.ref, Options{RunID: id, Concurrency: 1})
	if !errors.Is(err, ErrFailed) || res.State != StateFailed || res.Class != ClassDeployFailed {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if f.keyActive || f.rbCalls != 1 || f.count("rollback-deploy 1") != 3 {
		t.Fatalf("after resume: %v active=%v", f.log, f.keyActive)
	}
}

// A run in rolling_back that Resume gives up on keeps the key and opens the
// rollback_unconfirmed incident: a live service may hold the new key.
func TestResumeGiveUpInRollingBackOpensTheIncident(t *testing.T) {
	x, f := newFx(t), newRB(3)
	f.deployErr[cid(3)] = errors.New("boom")
	f.canErrs = -1 // never answers
	cfg := testResume
	cfg.MaxAttempts = 1
	s := NewService(New(x.pool, f.deps())).WithJournal(audit.NewJournal(x.pool)).WithResume(cfg)
	id, err := startPlain(s, x.ctx, x.ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wait()
	for i := 0; i < 3; i++ {
		time.Sleep(5 * time.Millisecond)
		if _, err := s.Resume(x.ctx); err != nil {
			t.Fatal(err)
		}
		s.Wait()
	}
	rep, err := s.Report(x.ctx, x.ref, id)
	if err != nil || !rep.Failed {
		t.Fatalf("the run must end failed: %+v %v", rep, err)
	}
	if !f.keyActive || f.rbCalls != 0 {
		t.Fatalf("the key was ended on give-up: %v", f.log)
	}
	if len(f.incidents) != 1 || f.incidents[0].Class != ClassRollbackUnconfirmed {
		t.Fatalf("incident: %+v", f.incidents)
	}
	var opened bool
	if err := x.pool.QueryRow(x.ctx, `SELECT incident_opened FROM rotation_runs WHERE id=$1`, id).Scan(&opened); err != nil || !opened {
		t.Fatalf("incident not recorded on the run: %v %v", opened, err)
	}
}
