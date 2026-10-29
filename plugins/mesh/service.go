package mesh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// This file rotates the service account of Keep itself: the Mesh agent whose
// token (right agent_key:rotate) the Provider uses. The account is rotated
// like any other agent key, with one difference: the new value goes into
// Keep's sealed store (a Sink) and nobody, no model and no log, sees it.

// ErrNoCurrent: the account does not have exactly one active key, so there is
// no "old key" to replace. Nothing is issued; a person looks at it.
var ErrNoCurrent = errors.New("mesh plugin: service account has no single active key")

// ErrOrphaned: a rotation did not finish and its new token is not the one in
// use. Two causes. A rotation of an account whose old token expires on its own
// failed after the new token was issued: the old token still works until its
// grace window ends; run RotateSelf again before then, or, when a staged value
// exists (RotateResult.NewKeyID), activate it through the sink. Or the lane
// restart behind a RestartHook failed or expired (joined with ErrHook): the
// new key was given up and, where the account allows it, the old one is back in use.
var ErrOrphaned = errors.New("mesh plugin: new token issued but not activated; the old one expires on its own")

// ErrSink: Keep's store refused to hold or activate the new token.
var ErrSink = errors.New("mesh plugin: token store failed")

// ErrHook: the after-activation hook failed. Its output is not forwarded.
var ErrHook = errors.New("mesh plugin: post-activation hook failed")

// ErrRestartPending is returned by a self-rotation whose queued restart has no
// outcome yet: the old key still stands, the caller should look again soon.
var ErrRestartPending = errors.New("mesh plugin: queued restart has no outcome yet")

// SelfRotator is the Mesh side of rotating the service account: issue the next
// token, confirm it works, end the old one. *Provider implements it over the
// agent-keys API; the extension actor that owns agent_key:rotate rotates its own
// ext_ token through a Mesh capability, which will be one more implementation
// of this interface. Errors are rotation classes.
type SelfRotator interface {
	// Account is the id of the service account, for hook events.
	Account() string
	// PerCallToken: calls are authenticated with the token read at call time,
	// so the old key can be ended by the new token after activation.
	PerCallToken() bool
	Current(ctx context.Context, subject string) (keyID string, ok bool, err error)
	Issue(ctx context.Context, req rotation.IssueRequest) (rotation.Issued, error)
	// AbandonKeepsNew: the replaced token stops working on its own soon after a
	// new one is issued (the ext_ account: a grace window) and Mesh cannot issue
	// the new one again. A rotation abandoned after Issue then keeps the staged
	// value and reports ErrOrphaned instead of rolling back to a dying token.
	AbandonKeepsNew() bool
	// Verify reports whether the key issued under keyID works at Mesh.
	Verify(ctx context.Context, keyID string) (rotation.Status, error)
	// Revoke ends keyID. For a key RotateSelf abandons before activation it
	// ends the new key; for the key being replaced it ends the old one.
	Revoke(ctx context.Context, keyID string) error
}

var _ SelfRotator = (*Provider)(nil)

// Account implements SelfRotator.
func (p *Provider) Account() string { return p.agent }

// Verify implements SelfRotator over the agent-keys listing.
func (p *Provider) Verify(ctx context.Context, keyID string) (rotation.Status, error) {
	return p.Check(ctx, keyID)
}

// AbandonKeepsNew implements SelfRotator: an agent key stays valid until revoked.
func (p *Provider) AbandonKeepsNew() bool { return false }

// PerCallToken implements SelfRotator.
func (p *Provider) PerCallToken() bool { return p.src != nil }

// Sink is Keep's side of the service token: it stages the new value sealed,
// switches the token source to it on Activate, and drops a staged value on
// Discard. Errors are classes; their text is not forwarded by this package.
type Sink interface {
	// Stage seals v before it returns; the sink must copy or seal it
	// synchronously and not keep v: the caller wipes it right after Stage.
	Stage(ctx context.Context, keyID string, v secret.Value) error
	Activate(ctx context.Context, keyID string) error
	Discard(ctx context.Context, keyID string) error
}

// HookEvent is all a hook is told: ids, never a value.
type HookEvent struct {
	AgentID string
	KeyID   string
}

// Hook runs after the new token is active. It lives outside Keep's core: the
// usual one relaunches the lane that holds the old token in its environment.
type Hook interface {
	AfterActivate(ctx context.Context, ev HookEvent) error
}

// RotateResult carries ids only.
type RotateResult struct {
	OldKeyID, NewKeyID string
	// HookFailed: the key was rotated but the hook did not succeed; the lane
	// still runs on the old (now revoked) token until it is relaunched.
	HookFailed bool
	// RestartID is the queued restart of a RestartHook: set once the request is
	// in the queue, while the old key still stands.
	RestartID uuid.UUID
	activated bool
	stageLost bool // the issued value was lost in Stage; the new key was ended, not kept
}

// RotateSelf replaces the service account's key.
//
//  1. exactly one active key must exist (the old one);
//  2. a second key is issued; the old one stays valid;
//  3. the value is staged in the sink and checked active at Mesh;
//  4. the sink activates it: from here the token source returns the new key;
//  5. the old key is revoked, now authenticated by the new token;
//  6. the hook runs.
//
// A failure up to step 4 ends the new key and leaves the old one in force.
// After step 4 there is no way back by design: a failed revoke of the old key
// is returned and is repeated with RevokeOld, a failed hook does not undo the rotation.
//
// With a RestartHook steps 5 and 6 change: the restart is queued and the old key
// is not ended; SettleRestart ends it after the poller's acknowledgement, or
// reports ErrOrphaned with both keys alive when the restart failed or expired.
func RotateSelf(ctx context.Context, p SelfRotator, sink Sink, hook Hook, run uuid.UUID) (RotateResult, error) {
	res, err := rotateSelf(ctx, p, sink, hook, run)
	if err != nil && res.NewKeyID != "" && !res.activated && !res.stageLost && p.AbandonKeepsNew() {
		err = errors.Join(ErrOrphaned, err)
	}
	return res, err
}

// keepStaged is a Sink whose Discard does nothing: the staged value of an
// orphaned rotation is the only token that will keep working.
type keepStaged struct{ Sink }

func (keepStaged) Discard(context.Context, string) error { return nil }

func rotateSelf(ctx context.Context, p SelfRotator, sink Sink, hook Hook, run uuid.UUID) (RotateResult, error) {
	// The old key is revoked with the token read after Activate: a provider
	// with a static token would call Mesh with the key it is ending and be
	// unusable afterwards. It needs a TokenSource.
	if !p.PerCallToken() {
		return RotateResult{}, ErrConfig
	}
	oldID, ok, err := p.Current(ctx, "")
	if err != nil {
		return RotateResult{}, err
	}
	if !ok {
		return RotateResult{}, ErrNoCurrent
	}
	iss, err := p.Issue(ctx, rotation.IssueRequest{Subject: p.Account(), RunID: run})
	if err != nil {
		return RotateResult{}, err
	}
	res := RotateResult{OldKeyID: oldID, NewKeyID: iss.KeyID}
	stored := sink
	if p.AbandonKeepsNew() {
		sink = keepStaged{sink}
	}
	// abandon ends the new key; it uses a context that survives a cancelled ctx.
	abandon := func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)
		defer cancel()
		_ = sink.Discard(bg, iss.KeyID)
		_ = p.Revoke(bg, iss.KeyID)
	}
	err = sink.Stage(ctx, iss.KeyID, iss.Value)
	if err != nil && p.AbandonKeepsNew() {
		// The issued token exists nowhere else: a lost Stage would leave the
		// account with no token once the old one's grace window ends. Try again
		// before the value is wiped.
		err = restage(ctx, sink, iss)
	}
	// The sink sealed its own copy; this one is not needed any more.
	iss.Value.Wipe()
	if err != nil {
		res.stageLost = true
		if p.AbandonKeepsNew() {
			// The value is gone, but Mesh cannot end a freshly issued ext_ token
			// (Revoke would send nothing) and the sink may hold a partly written
			// copy that is the only working one (Stage can commit and still
			// fail): neither Revoke nor Discard is called. The old token dies
			// after the grace window, so the caller is told to re-run at once.
			// The provider's own held plaintext is dropped locally.
			if f, ok := p.(interface{ Forget(string) }); ok {
				f.Forget(iss.KeyID)
			}
			return res, errors.Join(ErrOrphaned, ErrSink)
		}
		// An agent key can be ended: end the new one, the old key is the way
		// back. Only if ending it fails is the key an orphan for an operator.
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)
		defer cancel()
		_ = stored.Discard(bg, iss.KeyID)
		if rerr := p.Revoke(bg, iss.KeyID); rerr != nil {
			return res, errors.Join(ErrOrphaned, ErrSink, rerr)
		}
		return res, ErrSink
	}
	if st, err := p.Verify(ctx, iss.KeyID); err != nil || !st.Active {
		abandon()
		if err == nil {
			err = rotation.ErrNotFound
		}
		return res, err
	}
	if err := sink.Activate(ctx, iss.KeyID); err != nil {
		abandon()
		return res, ErrSink
	}
	res.activated = true
	return finish(ctx, p, hook, res)
}

// stageRetries and stageBackoff bound the retries of a failed Stage whose value
// is the only copy of a new token.
var (
	stageRetries = 3
	stageBackoff = 500 * time.Millisecond
)

func restage(ctx context.Context, sink Sink, iss rotation.Issued) error {
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)
	defer cancel()
	var err error
	for i := 0; i < stageRetries; i++ {
		select {
		case <-bg.Done():
			return err
		case <-time.After(stageBackoff):
		}
		if err = sink.Stage(bg, iss.KeyID, iss.Value); err == nil {
			return nil
		}
	}
	return err
}

// finish ends the old key and runs the hook. It is the forward-only tail of a
// rotation, shared by RotateSelf and RevokeOld.
func finish(ctx context.Context, p SelfRotator, hook Hook, res RotateResult) (RotateResult, error) {
	if rh, ok := hook.(*RestartHook); ok && rh != nil {
		// The lane restarts through the queue and the old key stays valid until
		// the poller says it did: SettleRestart ends it, or keeps both on a failure.
		id, err := rh.queue.Enqueue(ctx, res.NewKeyID)
		if err != nil {
			res.HookFailed = true
			return res, ErrHook
		}
		res.RestartID = id
		return res, nil
	}
	if err := p.Revoke(ctx, res.OldKeyID); err != nil {
		return res, err
	}
	if hook != nil {
		if hook.AfterActivate(ctx, HookEvent{AgentID: p.Account(), KeyID: res.NewKeyID}) != nil {
			res.HookFailed = true
		}
	}
	return res, nil
}

// RevokeOld repeats the tail of a rotation whose revoke of the old key failed
// (RotateSelf returned the result with an error after activation): it ends the
// old key and runs the hook. It refuses unless the new key is active at Mesh
// and the old key is another key, so it can never end the token in use. Call it
// with the RotateResult RotateSelf returned.
func RevokeOld(ctx context.Context, p SelfRotator, hook Hook, res RotateResult) (RotateResult, error) {
	if !p.PerCallToken() {
		return res, ErrConfig
	}
	if !rotation.ValidKeyID(res.OldKeyID) || !rotation.ValidKeyID(res.NewKeyID) || res.OldKeyID == res.NewKeyID {
		return res, ErrNoCurrent
	}
	st, err := p.Verify(ctx, res.NewKeyID)
	if err != nil {
		return res, err
	}
	if !st.Active {
		return res, ErrNoCurrent
	}
	return finish(ctx, p, hook, res)
}

// Restarts is the queue of lane restart requests as the plugin sees it, bound
// to the organization, the lane and the fingerprint of the active key by the
// core. Outcome reports whether the key counts as applied (the poller
// acknowledged ok or nothing_running) and whether the request is over.
type Restarts interface {
	Enqueue(ctx context.Context, keyVersion string) (uuid.UUID, error)
	Outcome(ctx context.Context, id uuid.UUID) (applied, final bool, err error)
}

// RestartHook asks for a lane restart through the queue instead of running a
// program on the server's host. With it RotateSelf does not end the old key:
// the result carries RestartID and SettleRestart finishes the rotation.
type RestartHook struct{ queue Restarts }

// NewRestartHook returns a hook over q.
func NewRestartHook(q Restarts) (*RestartHook, error) {
	if q == nil {
		return nil, ErrConfig
	}
	return &RestartHook{queue: q}, nil
}

// AfterActivate implements Hook for use outside RotateSelf: it queues a restart.
func (h *RestartHook) AfterActivate(ctx context.Context, ev HookEvent) error {
	if _, err := h.queue.Enqueue(ctx, ev.KeyID); err != nil {
		return ErrHook
	}
	return nil
}

// SettleRestart finishes a rotation whose restart was queued. Not over yet:
// settled is false and nothing changes. Acknowledged: the old key is ended.
// Failed or expired: nothing is ended and nothing is taken back. The lane may
// already have read the new token, so both keys stay valid and the error joins
// ErrOrphaned with ErrHook: a person looks at the lane and ends one of them.
func SettleRestart(ctx context.Context, p SelfRotator, q Restarts, res RotateResult) (RotateResult, bool, error) {
	if res.RestartID == uuid.Nil {
		return res, false, ErrConfig
	}
	applied, final, err := q.Outcome(ctx, res.RestartID)
	if err != nil {
		return res, false, err
	}
	if !final {
		return res, false, nil
	}
	if applied {
		// The old key is ended now for every rotator: an ext_ token's grace
		// window is a deadline, not the revocation.
		res, err = RevokeOld(ctx, p, nil, res)
		return res, err == nil, err
	}
	res.HookFailed = true
	return res, true, errors.Join(ErrOrphaned, ErrHook)
}

// ExecHook runs a fixed program. No shell, no value: the program gets
// KEEP_AGENT_ID and KEEP_KEY_ID and a closed environment, and its output is
// discarded, so nothing it prints can reach a log.
type ExecHook struct {
	argv    []string
	timeout time.Duration
}

// NewExecHook validates argv: a non-empty absolute program path.
func NewExecHook(argv []string) (*ExecHook, error) {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return nil, ErrConfig
	}
	return &ExecHook{argv: append([]string(nil), argv...), timeout: 60 * time.Second}, nil
}

// AfterActivate implements Hook.
func (h *ExecHook) AfterActivate(ctx context.Context, ev HookEvent) error {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.argv[0], h.argv[1:]...) //nolint:gosec // argv is operator configuration, absolute path, no shell
	cmd.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + os.Getenv("HOME"),
		"KEEP_AGENT_ID=" + ev.AgentID,
		"KEEP_KEY_ID=" + ev.KeyID,
	}
	if cmd.Run() != nil {
		return ErrHook
	}
	return nil
}
