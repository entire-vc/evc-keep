package mesh_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

// fakeRestarts is the restart queue as the plugin sees it; the outcome is set
// by the test, as the poller's acknowledgement would set it.
type fakeRestarts struct {
	enqueued       []string
	enqueueErr     error
	id             uuid.UUID
	applied, final bool
	outcomeCalls   int
}

func (q *fakeRestarts) Enqueue(_ context.Context, keyVersion string) (uuid.UUID, error) {
	if q.enqueueErr != nil {
		return uuid.Nil, q.enqueueErr
	}
	q.enqueued = append(q.enqueued, keyVersion)
	q.id = uuid.New()
	return q.id, nil
}

func (q *fakeRestarts) Outcome(context.Context, uuid.UUID) (bool, bool, error) {
	q.outcomeCalls++
	return q.applied, q.final, nil
}

func rotateWithQueue(t *testing.T, r *selfRig, q *fakeRestarts) mesh.RotateResult {
	t.Helper()
	hook, err := mesh.NewRestartHook(q)
	if err != nil {
		t.Fatal(err)
	}
	res, err := mesh.RotateSelf(context.Background(), r.p, r.sink, hook, uuid.New())
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	return res
}

// The restart is queued, the answer is immediate, the old key still stands.
func TestRestartHookQueuesAndKeepsTheOldKey(t *testing.T) {
	r := newSelfRig(t, "fresh-service-key")
	q := &fakeRestarts{}
	res := rotateWithQueue(t, r, q)
	if len(q.enqueued) != 1 || q.enqueued[0] != res.NewKeyID || res.RestartID != q.id || res.RestartID == uuid.Nil {
		t.Fatalf("queue %v, result %+v", q.enqueued, res)
	}
	if r.status(r.old) != "active" || r.status(res.NewKeyID) != "active" {
		t.Fatalf("old=%s new=%s: the old key must stand until the poller acknowledges", r.status(r.old), r.status(res.NewKeyID))
	}
	if q.outcomeCalls != 0 {
		t.Fatal("RotateSelf must not wait for the acknowledgement")
	}
}

func TestSettleRestartWaitsThenEndsTheOldKey(t *testing.T) {
	r := newSelfRig(t, "fresh-service-key")
	q := &fakeRestarts{}
	res := rotateWithQueue(t, r, q)
	ctx := context.Background()
	res, settled, err := mesh.SettleRestart(ctx, r.p, q, res)
	if err != nil || settled || r.status(r.old) != "active" {
		t.Fatalf("still open: settled=%v err=%v old=%s", settled, err, r.status(r.old))
	}
	q.applied, q.final = true, true
	res, settled, err = mesh.SettleRestart(ctx, r.p, q, res)
	if err != nil || !settled {
		t.Fatalf("acknowledged: settled=%v err=%v", settled, err)
	}
	if r.status(r.old) != "revoked" || r.status(res.NewKeyID) != "active" || r.sink.active != res.NewKeyID {
		t.Fatalf("old=%s new=%s active=%s", r.status(r.old), r.status(res.NewKeyID), r.sink.active)
	}
}

// failed and an expired TTL are both final and not applied. The lane may have
// read the new token before the restart failed, so neither key is ended and the
// store is not touched: both stay valid and a person decides.
func TestSettleRestartFailedOrExpiredKeepsBothKeysAlive(t *testing.T) {
	r := newSelfRig(t, "fresh-service-key")
	q := &fakeRestarts{}
	res := rotateWithQueue(t, r, q)
	q.applied, q.final = false, true
	res, settled, err := mesh.SettleRestart(context.Background(), r.p, q, res)
	if !settled || !errors.Is(err, mesh.ErrOrphaned) || !errors.Is(err, mesh.ErrHook) {
		t.Fatalf("settled=%v err=%v, want ErrOrphaned and ErrHook", settled, err)
	}
	if r.status(r.old) != "active" || r.status(res.NewKeyID) != "active" {
		t.Fatalf("old=%s new=%s: neither key may be ended", r.status(r.old), r.status(res.NewKeyID))
	}
	if got := strings.Join(r.sink.calls, ","); got != "stage,activate" {
		t.Fatalf("sink calls %s: the store must not be touched after the activation", got)
	}
}

func TestRestartHookEnqueueFailureLeavesTheOldKey(t *testing.T) {
	r := newSelfRig(t, "fresh-service-key")
	q := &fakeRestarts{enqueueErr: errors.New("queue down")}
	hook, _ := mesh.NewRestartHook(q)
	res, err := mesh.RotateSelf(context.Background(), r.p, r.sink, hook, uuid.New())
	if !errors.Is(err, mesh.ErrHook) || !res.HookFailed || res.RestartID != uuid.Nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if r.status(r.old) != "active" {
		t.Fatal("a rotation whose restart was not queued ended the old key")
	}
	if strings.Contains(err.Error(), "queue down") {
		t.Fatal("the queue's error text was forwarded")
	}
}

func TestRestartHookRefusesNilQueue(t *testing.T) {
	if _, err := mesh.NewRestartHook(nil); !errors.Is(err, mesh.ErrConfig) {
		t.Fatalf("nil queue: %v", err)
	}
	if _, _, err := mesh.SettleRestart(context.Background(), &fakeRotator{}, &fakeRestarts{}, mesh.RotateResult{}); !errors.Is(err, mesh.ErrConfig) {
		t.Fatalf("a result without a queued restart: %v", err)
	}
}

// The scheduler's closure keeps a queued rotation between ticks: no second
// rotation starts while the restart is open, and one starts after it settled.
func TestSelfRotationWaitsForTheRestartAcrossTicks(t *testing.T) {
	c := "ext_" + uuid.NewString()
	s := newStubExt(t, c)
	store := &tokenStore{token: c}
	q := &fakeRestarts{}
	run, err := mesh.NewSelfRotation(mesh.SelfRotateConfig{
		BaseURL: s.srv.URL, AccountID: uuid.NewString(), Store: store, Restarts: q,
	})
	if err != nil {
		t.Fatal(err)
	}
	next := "ext_" + uuid.NewString()
	s.nextTok, store.after = next, next
	ctx := context.Background()
	// While the restart has no outcome the run says so, so the scheduler
	// looks again inside the grace window rather than a whole interval later.
	if err := run(ctx); !errors.Is(err, mesh.ErrRestartPending) {
		t.Fatalf("tick 1: %v, want ErrRestartPending", err)
	}
	if len(q.enqueued) != 1 || store.calls() != "stage,activate" {
		t.Fatalf("tick 1: queue %v, store %q", q.enqueued, store.calls())
	}
	if err := run(ctx); !errors.Is(err, mesh.ErrRestartPending) || store.calls() != "stage,activate" || q.outcomeCalls != 1 {
		t.Fatalf("tick 2 (open): err=%v store=%q outcome calls=%d: a second rotation must not start", err, store.calls(), q.outcomeCalls)
	}
	q.applied, q.final = true, true
	if err := run(ctx); err != nil {
		t.Fatalf("tick 3 (acknowledged): %v", err)
	}
	next = "ext_" + uuid.NewString()
	s.nextTok, store.after = next, next
	if err := run(ctx); !errors.Is(err, mesh.ErrRestartPending) || len(q.enqueued) != 2 {
		t.Fatalf("tick 4: err=%v enqueued=%d, want a new rotation", err, len(q.enqueued))
	}
}

func TestSelfRotationRestartsExcludeTheHook(t *testing.T) {
	_, err := mesh.NewSelfRotation(mesh.SelfRotateConfig{
		BaseURL: "https://mesh.example", AccountID: uuid.NewString(), Store: &tokenStore{}, Restarts: &fakeRestarts{}, HookPath: "/bin/true",
	})
	if !errors.Is(err, mesh.ErrConfig) {
		t.Fatalf("queue and hook together: %v", err)
	}
}

// extOldStatus probes Mesh with the replaced token; only the status code leaves.
func extOldStatus(t *testing.T, r *extRig) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, r.s.srv.URL+"/api/v1/ext/me", nil)
	if err != nil {
		t.Fatal("probe request")
	}
	req.Header.Set("Authorization", "Bearer "+r.old)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("probe HTTP")
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// An acknowledged restart ends the replaced ext_ token at once; the grace
// window is only its deadline.
func TestSettleRestartEndsThePreviousExtToken(t *testing.T) {
	r := newExtRig(t, 300)
	q := &fakeRestarts{}
	hook, err := mesh.NewRestartHook(q)
	if err != nil {
		t.Fatal(err)
	}
	res, err := mesh.RotateSelf(context.Background(), r.x, r.store, hook, uuid.New())
	if err != nil {
		t.Fatal("rotate failed")
	}
	if len(q.enqueued) != 1 || r.s.previous == "" || len(r.s.delAuth) != 0 || extOldStatus(t, r) != http.StatusOK {
		t.Fatal("control: the old token must stand until the acknowledgement")
	}
	q.applied, q.final = true, true
	if _, settled, err := mesh.SettleRestart(context.Background(), r.x, q, res); err != nil || !settled {
		t.Fatalf("acknowledged: settled=%v err=%v", settled, err)
	}
	if st := extOldStatus(t, r); len(r.s.delAuth) != 1 || st != http.StatusUnauthorized {
		t.Fatalf("DELETE previous calls=%d, old token HTTP %d, want 1 and 401", len(r.s.delAuth), st)
	}
}

// After a failed or expired restart the scheduler starts no new rotation: with
// an ext_ token it would end the old token the lane may still run on.
func TestSelfRotationStaysFencedAfterAFailedRestart(t *testing.T) {
	r := newExtRig(t, 300)
	q := &fakeRestarts{}
	run, err := mesh.NewSelfRotation(mesh.SelfRotateConfig{BaseURL: r.s.srv.URL, AccountID: uuid.NewString(), Store: r.store, Restarts: q})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := run(ctx); !errors.Is(err, mesh.ErrRestartPending) || len(q.enqueued) != 1 || len(r.s.graceReq) != 1 {
		t.Fatalf("tick 1: err=%v enqueued=%d rotations=%d", err, len(q.enqueued), len(r.s.graceReq))
	}
	q.applied, q.final = false, true
	if err := run(ctx); !errors.Is(err, mesh.ErrOrphaned) || extOldStatus(t, r) != http.StatusOK {
		t.Fatalf("tick 2 (failed): err=%v, want ErrOrphaned and the old token alive", err)
	}
	for i := 0; i < 3; i++ {
		err := run(ctx)
		if st := extOldStatus(t, r); !errors.Is(err, mesh.ErrOrphaned) || len(r.s.graceReq) != 1 || len(q.enqueued) != 1 || len(r.s.delAuth) != 0 || st != http.StatusOK {
			t.Fatalf("retry %d: orphaned=%v rotations=%d enqueued=%d deletes=%d old token HTTP %d", i, errors.Is(err, mesh.ErrOrphaned), len(r.s.graceReq), len(q.enqueued), len(r.s.delAuth), st)
		}
	}
}

// With the queue the replaced ext_ token must outlive it: Mesh's default
// grace (300 s) would end the token the lane runs on before a slow restart is
// acknowledged or expires. A longer configured grace is kept.
func TestSelfRotationWithRestartsAsksForAGraceCoveringTheQueue(t *testing.T) {
	for _, tc := range []struct {
		name     string
		grace    int
		restarts bool
		wantBody string
	}{
		{"queue, default grace", 0, true, `{"grace_seconds":1200}`},
		{"queue, shorter grace", 300, true, `{"grace_seconds":1200}`},
		{"queue, longer grace", 3000, true, `{"grace_seconds":3000}`},
		{"no queue", 0, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := "ext_" + uuid.NewString()
			s := newStubExt(t, c)
			store := &tokenStore{token: c}
			cfg := mesh.SelfRotateConfig{BaseURL: s.srv.URL, AccountID: uuid.NewString(), Store: store, GraceSeconds: tc.grace}
			if tc.restarts {
				cfg.Restarts = &fakeRestarts{}
			}
			run, err := mesh.NewSelfRotation(cfg)
			if err != nil {
				t.Fatal(err)
			}
			next := "ext_" + uuid.NewString()
			s.nextTok, store.after = next, next
			_ = run(context.Background())
			if len(s.graceReq) != 1 || s.graceReq[0] != tc.wantBody {
				t.Fatalf("rotate bodies %q, want one %q", s.graceReq, tc.wantBody)
			}
		})
	}
}
