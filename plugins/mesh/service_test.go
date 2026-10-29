package mesh_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	"github.com/entire-vc/evc-keep/pkg/provider/svctoken"
	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

// fakeSink stands in for Keep's sealed store of the service token. It holds
// the staged value only as a secret.Value and the staged/active key ids.
type fakeSink struct {
	mu                      sync.Mutex
	staged, active          string
	failStage, failActivate error
	onStage                 func()
	got                     secret.Value
	calls                   []string
	vlen                    int
}

func (f *fakeSink) Stage(_ context.Context, keyID string, v secret.Value) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "stage")
	if f.onStage != nil {
		f.onStage()
	}
	if f.failStage != nil {
		return f.failStage
	}
	f.staged, f.vlen, f.got = keyID, v.Len(), v
	return nil
}

func (f *fakeSink) Activate(_ context.Context, keyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "activate")
	if f.failActivate != nil {
		return f.failActivate
	}
	f.active, f.staged = keyID, ""
	return nil
}

func (f *fakeSink) Discard(_ context.Context, keyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "discard")
	if f.staged == keyID {
		f.staged = ""
	}
	return nil
}

type fakeHook struct {
	ev  []mesh.HookEvent
	err error
}

func (h *fakeHook) AfterActivate(_ context.Context, ev mesh.HookEvent) error {
	h.ev = append(h.ev, ev)
	return h.err
}

// selfRig is a service account with one active key (its token) on the stub.
type selfRig struct {
	s    *stubMesh
	p    *mesh.Provider
	sink *fakeSink
	hook *fakeHook
	old  string
	logs *bytes.Buffer
}

func newSelfRig(t *testing.T, value string) *selfRig {
	t.Helper()
	agent := uuid.NewString()
	s := newStub(t, agent, value)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p, err := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent, Log: log,
		TokenSource: func(context.Context) (mesh.Token, error) { return stubToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	old := uuid.NewString()
	s.mu.Lock()
	s.keys[old] = "active"
	s.mu.Unlock()
	return &selfRig{s: s, p: p, sink: &fakeSink{}, hook: &fakeHook{}, old: old, logs: &logs}
}

func (r *selfRig) status(id string) string {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.s.keys[id]
}

func TestRotateSelfHappyPath(t *testing.T) {
	r := newSelfRig(t, "fresh-service-key")
	res, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if r.status(r.old) != "revoked" || r.status(res.NewKeyID) != "active" {
		t.Fatalf("old=%s new=%s", r.status(r.old), r.status(res.NewKeyID))
	}
	if res.OldKeyID != r.old || r.sink.active != res.NewKeyID || r.sink.vlen != len("fresh-service-key") {
		t.Fatalf("result %+v sink %+v", res, r.sink)
	}
	if got := strings.Join(r.sink.calls, ","); got != "stage,activate" {
		t.Fatalf("order %s", got)
	}
	if len(r.hook.ev) != 1 || r.hook.ev[0].KeyID != res.NewKeyID {
		t.Fatalf("hook %+v", r.hook.ev)
	}
}

// Failing before activation ends the new key and leaves the old one valid.
func TestRotateSelfRollsBackBeforeActivation(t *testing.T) {
	for name, set := range map[string]func(*selfRig){
		"stage":    func(r *selfRig) { r.sink.failStage = errors.New("disk full") },
		"activate": func(r *selfRig) { r.sink.failActivate = errors.New("sealer down") },
	} {
		t.Run(name, func(t *testing.T) {
			r := newSelfRig(t, "fresh-service-key")
			set(r)
			_, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New())
			if err == nil {
				t.Fatal("expected an error")
			}
			if r.status(r.old) != "active" {
				t.Fatalf("old key must stay active, is %q", r.status(r.old))
			}
			r.s.mu.Lock()
			for id, st := range r.s.keys {
				if id != r.old && st == "active" {
					t.Fatalf("new key %s left active", id)
				}
			}
			r.s.mu.Unlock()
			if len(r.hook.ev) != 0 {
				t.Fatal("hook ran without activation")
			}
			if last := r.sink.calls[len(r.sink.calls)-1]; last != "discard" {
				t.Fatalf("staged value not discarded: %v", r.sink.calls)
			}
			if strings.Contains(err.Error(), "disk full") || strings.Contains(err.Error(), "sealer down") {
				t.Fatalf("sink error text forwarded: %v", err)
			}
		})
	}
}

// Without exactly one active key the account is not rotated: nothing is issued.
func TestRotateSelfRefusesAmbiguousCurrent(t *testing.T) {
	r := newSelfRig(t, "v")
	r.s.mu.Lock()
	r.s.keys[uuid.NewString()] = "active"
	r.s.mu.Unlock()
	if _, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New()); !errors.Is(err, mesh.ErrNoCurrent) {
		t.Fatalf("got %v", err)
	}
	if len(r.sink.calls) != 0 {
		t.Fatalf("sink touched: %v", r.sink.calls)
	}
}

// A hook failure is reported but does not undo the rotation.
func TestRotateSelfHookFailureKeepsRotation(t *testing.T) {
	r := newSelfRig(t, "v")
	r.hook.err = errors.New("relaunch failed: " + "secret-looking-text")
	res, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if !res.HookFailed || r.status(r.old) != "revoked" {
		t.Fatalf("res %+v old %s", res, r.status(r.old))
	}
}

// The new key value and the token never reach a log, an error or a result.
func TestRotateSelfCanaryDoesNotSurface(t *testing.T) {
	c := canary.New()
	r := newSelfRig(t, c.Value(0))
	r.s.note = c.Value(1)
	res, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	r2 := newSelfRig(t, c.Value(0))
	r2.s.mu.Lock()
	r2.s.failTxt = `{"key":"` + c.Value(0) + `"}`
	r2.s.mu.Unlock()
	r2.sink.failActivate = errors.New(c.Value(0))
	_, err2 := mesh.RotateSelf(context.Background(), r2.p, r2.sink, r2.hook, uuid.New())
	if err2 == nil {
		t.Fatal("expected error")
	}
	all := r.logs.String() + r2.logs.String() + err2.Error() + res.NewKeyID + res.OldKeyID
	if c.In(all) {
		t.Fatalf("canary surfaced: %s", all)
	}
	if !strings.Contains(r.logs.String(), "issue") {
		t.Fatal("positive control: rotation not journaled")
	}
}

// TokenSource is asked for the token on every call: nothing is cached, so a
// token swapped by Keep takes effect at once and an old one is not reused.
func TestTokenSourceIsPerCall(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	n := 0
	src := func(context.Context) (mesh.Token, error) {
		n++
		if n == 1 {
			return "wrong-token", nil
		}
		return stubToken, nil
	}
	p, err := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent, TokenSource: src, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := p.Current(ctx, "x"); !errors.Is(err, rotation.ErrDenied) {
		t.Fatalf("first call should be denied: %v", err)
	}
	if _, _, err := p.Current(ctx, "x"); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if n != 2 {
		t.Fatalf("token fetched %d times for 2 calls", n)
	}
	// A failing source is a closed error class with no text from the source.
	bad, _ := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent,
		TokenSource: func(context.Context) (mesh.Token, error) { return "", errors.New("vault says hunter2") }})
	_, _, err = bad.Current(ctx, "x")
	if !errors.Is(err, rotation.ErrUnavailable) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("source error: %v", err)
	}
	// New needs a token or a source.
	if _, err := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent}); !errors.Is(err, mesh.ErrConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestExecHook(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	script := filepath.Join(dir, "hook.sh")
	body := "#!/bin/sh\necho \"$KEEP_AGENT_ID $KEEP_KEY_ID $#\" > " + out + "\necho noisy-secret-looking-output\ntest ! -e " + filepath.Join(dir, "fail") + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	h, err := mesh.NewExecHook([]string{script, "lane-relaunch"})
	if err != nil {
		t.Fatal(err)
	}
	ev := mesh.HookEvent{AgentID: uuid.NewString(), KeyID: uuid.NewString()}
	if err := h.AfterActivate(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Clean(out))
	if strings.TrimSpace(string(got)) != ev.AgentID+" "+ev.KeyID+" 1" {
		t.Fatalf("hook got %q", got)
	}
	// Environment is closed: a canary in the parent env does not reach the hook.
	c := canary.New()
	t.Setenv("MESH_SERVICE_TOKEN", c.Value(0))
	if err := os.WriteFile(filepath.Join(dir, "fail"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err = h.AfterActivate(context.Background(), ev)
	if !errors.Is(err, mesh.ErrHook) || strings.Contains(err.Error(), "noisy") {
		t.Fatalf("exit 3: %v", err)
	}
	for _, bad := range [][]string{nil, {}, {"relative/bin"}, {""}} {
		if _, err := mesh.NewExecHook(bad); !errors.Is(err, mesh.ErrConfig) {
			t.Fatalf("argv %q accepted: %v", bad, err)
		}
	}
}

func TestExecHookEnvIsClosed(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "env")
	script := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n/usr/bin/env > "+out+"\n"), 0o700); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	c := canary.New()
	t.Setenv("MESH_SERVICE_TOKEN", c.Value(0))
	h, err := mesh.NewExecHook([]string{script})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AfterActivate(context.Background(), mesh.HookEvent{AgentID: uuid.NewString(), KeyID: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Clean(out))
	if len(got) == 0 {
		t.Fatal("positive control: hook env not captured")
	}
	if strings.Contains(string(got), "/opt/homebrew") {
		t.Fatalf("user-writable dir on the hook PATH: %s", got)
	}
	if c.In(string(got)) || strings.Contains(string(got), "MESH_SERVICE_TOKEN") {
		t.Fatalf("parent env leaked into hook: %s", got)
	}
}

// A new key Mesh does not list as active is never activated.
func TestRotateSelfRequiresActiveNewKey(t *testing.T) {
	r := newSelfRig(t, "v")
	r.s.mu.Lock()
	r.s.newStat = "pending"
	r.s.mu.Unlock()
	_, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New())
	if err == nil {
		t.Fatal("rotation went through with an inactive new key")
	}
	if !errors.Is(err, rotation.ErrNotFound) {
		t.Fatalf("class: %v", err)
	}
	if r.sink.active != "" || r.status(r.old) != "active" {
		t.Fatalf("activated=%q old=%s", r.sink.active, r.status(r.old))
	}
}

// Rollback must not depend on the caller's context: a cancelled run still
// ends the new key and drops the staged value.
func TestRotateSelfRollbackSurvivesCancelledContext(t *testing.T) {
	r := newSelfRig(t, "v")
	ctx, cancel := context.WithCancel(context.Background())
	r.sink.failStage = errors.New("x")
	r.sink.onStage = cancel
	if _, err := mesh.RotateSelf(ctx, r.p, r.sink, r.hook, uuid.New()); err == nil {
		t.Fatal("expected an error")
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for id, st := range r.s.keys {
		if id != r.old && st == "active" {
			t.Fatalf("new key %s left active after a cancelled run", id)
		}
	}
	if r.sink.calls[len(r.sink.calls)-1] != "discard" {
		t.Fatalf("calls %v", r.sink.calls)
	}
}

// A failed revoke of the old key is returned (so it can be repeated), after
// activation, and the hook does not run on a half-finished rotation.
func TestRotateSelfOldKeyRevokeFailureReturned(t *testing.T) {
	r := newSelfRig(t, "v")
	r.s.mu.Lock()
	r.s.delFailID = r.old
	r.s.mu.Unlock()
	res, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New())
	if !errors.Is(err, rotation.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	if res.NewKeyID == "" || r.sink.active != res.NewKeyID || len(r.hook.ev) != 0 {
		t.Fatalf("res %+v active %q hook %d", res, r.sink.active, len(r.hook.ev))
	}
}

func TestTokenSourceEmptyAndPrecedence(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	ctx := context.Background()
	empty, _ := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent,
		TokenSource: func(context.Context) (mesh.Token, error) { return "", nil }})
	if _, _, err := empty.Current(ctx, "x"); !errors.Is(err, rotation.ErrUnavailable) {
		t.Fatalf("empty token from source: %v", err)
	}
	// Both set: the source wins over the static token.
	both, _ := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent, Token: "stale-static-token",
		TokenSource: func(context.Context) (mesh.Token, error) { return stubToken, nil }})
	if _, _, err := both.Current(ctx, "x"); err != nil {
		t.Fatalf("source must win over Token: %v", err)
	}
}

// The token that comes from a TokenSource is the canary here: it must not
// reach a log, an error or a printed result on a good run, on a denial and on
// a transport failure.
func TestSourceTokenCanaryDoesNotSurface(t *testing.T) {
	c := canary.New()
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	s.token = "ext_" + c.Value(2)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tok := "ext_" + c.Value(2)
	mk := func(base, token string) *mesh.Provider {
		p, err := mesh.New(mesh.Config{BaseURL: base, AgentID: agent, Log: log,
			TokenSource: func(context.Context) (mesh.Token, error) { return mesh.Token(token), nil }})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	ctx := context.Background()
	var out []string
	good := mk(s.srv.URL, tok)
	s.mu.Lock()
	s.keys[uuid.NewString()] = "active"
	s.mu.Unlock()
	res, err := mesh.RotateSelf(ctx, good, &fakeSink{}, &fakeHook{}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, fmt.Sprintf("%+v|%v|%+v", res, good, *good))
	if _, _, err := mk(s.srv.URL, c.Value(1)).Current(ctx, "x"); err == nil {
		t.Fatal("wrong token accepted")
	} else {
		out = append(out, err.Error())
	}
	s.srv.Close()
	if _, _, err := mk(s.srv.URL, tok).Current(ctx, "x"); err == nil {
		t.Fatal("closed server answered")
	} else {
		out = append(out, err.Error())
	}
	if !strings.Contains(logs.String(), "issue") {
		t.Fatal("positive control: nothing journaled")
	}
	if c.In(logs.String() + strings.Join(out, "\n")) {
		t.Fatalf("source token surfaced: %s %v", logs.String(), out)
	}
}

func TestRotateSelfNeedsTokenSource(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	p := newProvider(t, s, &bytes.Buffer{}) // static token
	sink := &fakeSink{}
	if _, err := mesh.RotateSelf(context.Background(), p, sink, nil, uuid.New()); !errors.Is(err, mesh.ErrConfig) {
		t.Fatalf("got %v", err)
	}
	if len(sink.calls) != 0 || len(s.keys) != 0 {
		t.Fatal("something was issued")
	}
}

// The issued value is wiped once the sink holds its own sealed copy.
func TestRotateSelfWipesIssuedValue(t *testing.T) {
	r := newSelfRig(t, "wipe-me-please")
	if _, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New()); err != nil {
		t.Fatal(err)
	}
	secret.Expose(r.sink.got, func(b []byte) {
		for i, c := range b {
			if c != 0 {
				t.Fatalf("issued value was not wiped: byte %d of %d is non-zero", i, len(b))
			}
		}
	})
}

// After a failed revoke of the old key, RevokeOld finishes the rotation: the
// old key ends, the hook runs once, and a repeat is harmless.
func TestRevokeOldRepeatsFailedRevoke(t *testing.T) {
	r := newSelfRig(t, "v")
	r.s.mu.Lock()
	r.s.delFailID = r.old
	r.s.mu.Unlock()
	ctx := context.Background()
	res, err := mesh.RotateSelf(ctx, r.p, r.sink, r.hook, uuid.New())
	if err == nil || len(r.hook.ev) != 0 {
		t.Fatalf("setup: %v hook %d", err, len(r.hook.ev))
	}
	// Two active keys: a second RotateSelf has nothing to replace; that is
	// exactly the dead end RevokeOld exists for.
	if _, err := mesh.RotateSelf(ctx, r.p, r.sink, r.hook, uuid.New()); !errors.Is(err, mesh.ErrNoCurrent) {
		t.Fatalf("second RotateSelf: %v", err)
	}
	r.s.mu.Lock()
	r.s.delFailID = ""
	r.s.mu.Unlock()
	out, err := mesh.RevokeOld(ctx, r.p, r.hook, res)
	if err != nil {
		t.Fatal(err)
	}
	if r.status(r.old) != "revoked" || r.status(res.NewKeyID) != "active" || out.HookFailed || len(r.hook.ev) != 1 {
		t.Fatalf("old=%s new=%s hook=%d %+v", r.status(r.old), r.status(res.NewKeyID), len(r.hook.ev), out)
	}
	if _, err := mesh.RevokeOld(ctx, r.p, r.hook, res); err != nil {
		t.Fatalf("repeat: %v", err)
	}
}

// RevokeOld never ends a key unless the new one is active and different.
func TestRevokeOldRefusals(t *testing.T) {
	r := newSelfRig(t, "v")
	ctx := context.Background()
	newID := uuid.NewString()
	r.s.mu.Lock()
	r.s.keys[newID] = "revoked"
	r.s.mu.Unlock()
	cases := map[string]mesh.RotateResult{
		"new inactive": {OldKeyID: r.old, NewKeyID: newID},
		"new unknown":  {OldKeyID: r.old, NewKeyID: uuid.NewString()},
		"same":         {OldKeyID: r.old, NewKeyID: r.old},
		"bad old id":   {OldKeyID: "../x", NewKeyID: r.old},
		"empty":        {},
	}
	for name, res := range cases {
		if _, err := mesh.RevokeOld(ctx, r.p, r.hook, res); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if r.status(r.old) != "active" || len(r.hook.ev) != 0 || r.s.delSeen != 0 {
		t.Fatalf("something was ended: old=%s hook=%d del=%d", r.status(r.old), len(r.hook.ev), r.s.delSeen)
	}
	static := newProvider(t, r.s, &bytes.Buffer{})
	if _, err := mesh.RevokeOld(ctx, static, nil, mesh.RotateResult{OldKeyID: r.old, NewKeyID: newID}); !errors.Is(err, mesh.ErrConfig) {
		t.Fatalf("static token: %v", err)
	}
}

// Mesh's agent_key:rotate is an ext_ actor: an agent key as Bearer is refused.
func TestAgentKeyAsBearerIsDenied(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	// The stub's expected token is the agent key itself: the value matches, so
	// only the ext_ rule can refuse it.
	s.token = "agk_only-an-agent-key"
	p, err := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent,
		TokenSource: func(context.Context) (mesh.Token, error) { return "agk_only-an-agent-key", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := p.Current(ctx, ""); !errors.Is(err, rotation.ErrDenied) {
		t.Fatalf("agk_ bearer accepted: %v", err)
	}
	if _, err := p.Issue(ctx, rotation.IssueRequest{RunID: uuid.New()}); !errors.Is(err, rotation.ErrDenied) {
		t.Fatalf("agk_ bearer issued: %v", err)
	}
}

// fakeRotator is a SelfRotator that is not the agent-keys Provider: the
// extension-actor implementation will look like this to RotateSelf.
type fakeRotator struct {
	calls   []string
	perc    bool
	subject string
	revoked []string
}

const fakeAccount = "00000000-0000-4000-8000-000000000001"

func (f *fakeRotator) Account() string       { return fakeAccount }
func (f *fakeRotator) PerCallToken() bool    { return f.perc }
func (f *fakeRotator) AbandonKeepsNew() bool { return false }
func (f *fakeRotator) Current(context.Context, string) (string, bool, error) {
	f.calls = append(f.calls, "current")
	return uuid.NewString(), true, nil
}
func (f *fakeRotator) Issue(_ context.Context, req rotation.IssueRequest) (rotation.Issued, error) {
	f.subject = req.Subject
	f.calls = append(f.calls, "issue")
	return rotation.Issued{KeyID: uuid.NewString(), Value: secret.New([]byte("ext_x"))}, nil
}
func (f *fakeRotator) Verify(context.Context, string) (rotation.Status, error) {
	f.calls = append(f.calls, "check")
	return rotation.Status{Active: true}, nil
}
func (f *fakeRotator) Revoke(_ context.Context, id string) error {
	f.calls = append(f.calls, "revoke")
	f.revoked = append(f.revoked, id)
	return nil
}

func TestRotateSelfRunsOverAnySelfRotator(t *testing.T) {
	f := &fakeRotator{perc: true}
	sink := &fakeSink{}
	if _, err := mesh.RotateSelf(context.Background(), f, sink, nil, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls, ","); got != "current,issue,check,revoke" {
		t.Fatalf("order %s", got)
	}
	if f.subject != fakeAccount {
		t.Fatalf("issued for subject %q", f.subject)
	}
	if _, err := mesh.RotateSelf(context.Background(), &fakeRotator{}, sink, nil, uuid.New()); !errors.Is(err, mesh.ErrConfig) {
		t.Fatalf("without per-call token: %v", err)
	}
}

// Keep's own sealed store as both Sink and TokenSource, end to end: the new
// token is sealed, becomes the token the next call uses, and the old key is
// ended with that new token.
func TestRotateSelfThroughKeepStore(t *testing.T) {
	ctx := context.Background()
	store, err := svctoken.New(memory.New(nil), "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	seed := uuid.NewString()
	if err := store.Stage(ctx, seed, secret.New([]byte(stubToken))); err != nil || store.Activate(ctx, seed) != nil {
		t.Fatal("seed token")
	}
	agent := uuid.NewString()
	s := newStub(t, agent, "ext_rotated-token")
	old := uuid.NewString()
	s.keys[old] = "active"
	s.accept = map[string]bool{"Bearer ext_rotated-token": true}
	src := func(ctx context.Context) (mesh.Token, error) {
		tok, err := store.Token(ctx)
		return mesh.Token(tok), err
	}
	p, err := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent, TokenSource: src})
	if err != nil {
		t.Fatal(err)
	}
	res, err := mesh.RotateSelf(ctx, p, store, nil, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if tok, _ := store.Token(ctx); tok != "ext_rotated-token" {
		t.Fatalf("token after rotation has length %d", len(tok))
	}
	if n := len(s.delAuth); n != 1 || s.delAuth[0] != "Bearer ext_rotated-token" {
		t.Fatalf("old key must be ended with the new token: %d calls", n)
	}
	if s.keys[old] != "revoked" || s.keys[res.NewKeyID] != "active" {
		t.Fatalf("old=%s new=%s", s.keys[old], s.keys[res.NewKeyID])
	}
}

// A malformed old key id is refused before the rotator is asked to revoke it.
func TestRevokeOldBadIDNeverReachesRotator(t *testing.T) {
	f := &fakeRotator{perc: true}
	for _, old := range []string{"", "../x", strings.ToUpper(uuid.NewString())} {
		if _, err := mesh.RevokeOld(context.Background(), f, nil,
			mesh.RotateResult{OldKeyID: old, NewKeyID: uuid.NewString()}); err == nil {
			t.Errorf("old id %q accepted", old)
		}
	}
	if len(f.revoked) != 0 {
		t.Fatalf("revoked %v", f.revoked)
	}
}

// allZero reports whether every byte of v is zero (v was wiped).
func allZero(v secret.Value) bool {
	zero := true
	secret.Expose(v, func(b []byte) {
		for _, c := range b {
			if c != 0 {
				zero = false
			}
		}
	})
	return zero
}

// Agent keys can be ended: a lost Stage ends the new key (ErrSink only), and
// the old key stays active.
func TestProviderStageFailureEndsNewKey(t *testing.T) {
	defer mesh.NoStageBackoff()()
	r := newSelfRig(t, "v")
	r.sink.failStage = errors.New("disk")
	sink := &capSink{fakeSink: r.sink}
	_, err := mesh.RotateSelf(context.Background(), r.p, sink, r.hook, uuid.New())
	if !errors.Is(err, mesh.ErrSink) || errors.Is(err, mesh.ErrOrphaned) || err.Error() != mesh.ErrSink.Error() {
		t.Fatalf("got %v", err)
	}
	if !allZero(sink.v) {
		t.Fatal("the issued value was not wiped")
	}
	if r.status(r.old) != "active" {
		t.Fatalf("old key is %q", r.status(r.old))
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for id, st := range r.s.keys {
		if id != r.old && st == "active" {
			t.Fatal("the new key is still active")
		}
	}
}

// If ending the new agent key fails too, it is an orphan: ErrOrphaned, ErrSink
// and the revoke error together.
func TestProviderStageFailureRevokeFailsOrphaned(t *testing.T) {
	defer mesh.NoStageBackoff()()
	r := newSelfRig(t, "v")
	r.sink.failStage = errors.New("disk")
	r.s.mu.Lock()
	r.s.delFail = 100
	r.s.mu.Unlock()
	_, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New())
	if !errors.Is(err, mesh.ErrOrphaned) || !errors.Is(err, mesh.ErrSink) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "ext_") {
		t.Fatal("a token surfaced")
	}
}

// A cancelled caller context must not leave the new agent key alive: the
// rollback runs on a context that survives cancellation, after a lost Stage
// and after a failed Verify.
func TestProviderRollbackSurvivesCancelledContext(t *testing.T) {
	defer mesh.NoStageBackoff()()
	for name, failStage := range map[string]error{"stage-lost": errors.New("disk"), "verify-fails": nil} {
		t.Run(name, func(t *testing.T) {
			r := newSelfRig(t, "v")
			ctx, cancel := context.WithCancel(context.Background())
			r.sink.failStage = failStage
			r.sink.onStage = cancel
			_, err := mesh.RotateSelf(ctx, r.p, r.sink, r.hook, uuid.New())
			if err == nil {
				t.Fatal("rotation succeeded on a cancelled context")
			}
			r.s.mu.Lock()
			defer r.s.mu.Unlock()
			for id, st := range r.s.keys {
				if id != r.old && st == "active" {
					t.Fatal("the new key is still active after the rollback")
				}
			}
		})
	}
}
