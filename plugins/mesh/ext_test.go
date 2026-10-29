package mesh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// stubExtMesh stands in for Mesh's ext-token routes (contract of the
// ext_token:self_rotate capability). Tokens are fake and in-process.
type stubExtMesh struct {
	mu        sync.Mutex
	current   string
	previous  string
	noCap     bool   // POST answers 403
	answer    string // when set, POST answers this body instead of a token
	meFailNew int    // GET /me with the newest token answers this status
	rejectNew bool   // a token issued by POST is refused by GET /me
	newest    string
	delFail   int
	graceReq  []string // body of every POST
	calls     []string // "METHOD path" in order
	delAuth   []string
	nextTok   string // value POST issues; random when empty
	failReply int    // POST rotates, then answers this status
	dropReply bool   // POST rotates, then the connection is cut without a body
	srv       *httptest.Server
}

func newStubExt(t *testing.T, current string) *stubExtMesh {
	s := &stubExtMesh{current: current}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubExtMesh) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, r.Method+" "+r.URL.Path)
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ext_") || (tok != s.current && (tok != s.previous || tok == "")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/ext/me":
		if s.meFailNew != 0 && tok == s.newest {
			w.WriteHeader(s.meFailNew)
			return
		}
		if s.rejectNew && tok == s.newest {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"actor":"ext:x"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/ext/me/token/rotate":
		b, _ := io.ReadAll(r.Body)
		s.graceReq = append(s.graceReq, string(b))
		if s.noCap {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if s.answer != "" {
			_, _ = w.Write([]byte(s.answer))
			return
		}
		nt := s.nextTok
		if nt == "" {
			nt = "ext_" + uuid.NewString()
		}
		s.previous, s.current, s.newest = tok, nt, nt
		w.Header().Set("Cache-Control", "no-store")
		if s.failReply != 0 {
			w.WriteHeader(s.failReply)
			return
		}
		if s.dropReply {
			if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = c.Close()
			}
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"extension_token": nt, "token_prefix": nt[:8], "token_length": len(nt),
			"actor_id": uuid.NewString(), "previous_valid_for": 300,
		})
	case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/ext/me/token/previous":
		s.delAuth = append(s.delAuth, tok)
		if s.delFail > 0 {
			s.delFail--
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if tok != s.current {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		s.previous = ""
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

type extRig struct {
	s     *stubExtMesh
	x     *mesh.ExtSelf
	store *svctoken.Store
	hook  *fakeHook
	logs  *bytes.Buffer
	old   string
}

func newExtRig(t *testing.T, grace int) *extRig {
	t.Helper()
	ctx := context.Background()
	old := "ext_" + uuid.NewString()
	s := newStubExt(t, old)
	store, err := svctoken.New(memory.New(nil), "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	seed := uuid.NewString()
	if err := store.Stage(ctx, seed, secret.New([]byte(old))); err != nil || store.Activate(ctx, seed) != nil {
		t.Fatal("seed token")
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	x, err := mesh.NewExtSelf(mesh.ExtConfig{BaseURL: s.srv.URL, AccountID: uuid.NewString(), GraceSeconds: grace, Log: log,
		TokenSource: func(ctx context.Context) (mesh.Token, error) {
			tok, err := store.Token(ctx)
			return mesh.Token(tok), err
		}})
	if err != nil {
		t.Fatal(err)
	}
	return &extRig{s: s, x: x, store: store, hook: &fakeHook{}, logs: &logs, old: old}
}

func (r *extRig) token(t *testing.T) string {
	t.Helper()
	tok, err := r.store.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestExtRotateSelfHappyPath(t *testing.T) {
	r := newExtRig(t, 0)
	res, err := mesh.RotateSelf(context.Background(), r.x, r.store, r.hook, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if got := r.token(t); got != r.s.current || got == r.old {
		t.Fatal("Keep's token is not the newly issued one")
	}
	want := []string{"GET /api/v1/ext/me", "POST /api/v1/ext/me/token/rotate", "GET /api/v1/ext/me", "DELETE /api/v1/ext/me/token/previous"}
	if strings.Join(r.s.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls %v", r.s.calls)
	}
	if len(r.s.delAuth) != 1 || r.s.delAuth[0] != r.s.current {
		t.Fatal("previous token must be ended with the new token")
	}
	if r.s.previous != "" || len(r.hook.ev) != 1 || res.NewKeyID == res.OldKeyID {
		t.Fatalf("previous %q hook %d %+v", r.s.previous, len(r.hook.ev), res)
	}
	// The old token is dead now.
	oldRej, _ := http.NewRequest(http.MethodGet, r.s.srv.URL+"/api/v1/ext/me", nil)
	oldRej.Header.Set("Authorization", "Bearer "+r.old)
	if resp, err := http.DefaultClient.Do(oldRej); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token still works: %v", err)
	}
}

func TestExtGraceSecondsSent(t *testing.T) {
	r := newExtRig(t, 120)
	if _, err := mesh.RotateSelf(context.Background(), r.x, r.store, nil, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if len(r.s.graceReq) != 1 || r.s.graceReq[0] != `{"grace_seconds":120}` {
		t.Fatalf("body %v", r.s.graceReq)
	}
	r2 := newExtRig(t, 0)
	if _, err := mesh.RotateSelf(context.Background(), r2.x, r2.store, nil, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if r2.s.graceReq[0] != "" {
		t.Fatalf("default grace must send no body, got %q", r2.s.graceReq[0])
	}
}

// Failing before activation leaves the old token as Keep's token, sends no
// DELETE (it would end the token in use) and drops the new value.
func TestExtRollsBackBeforeActivation(t *testing.T) {
	for name, set := range map[string]func(*extRig, *fakeSink){
		"verify":             func(r *extRig, _ *fakeSink) { r.s.rejectNew = true },
		"verify-unavailable": func(r *extRig, _ *fakeSink) { r.s.meFailNew = http.StatusServiceUnavailable },
		"stage":              func(_ *extRig, sk *fakeSink) { sk.failStage = errors.New("disk") },
		"activate":           func(_ *extRig, sk *fakeSink) { sk.failActivate = errors.New("disk") },
	} {
		t.Run(name, func(t *testing.T) {
			r := newExtRig(t, 0)
			sink := &fakeSink{}
			set(r, sink)
			var s mesh.Sink = r.store
			if name != "verify" && name != "verify-unavailable" {
				s = sink
			}
			if _, err := mesh.RotateSelf(context.Background(), r.x, s, r.hook, uuid.New()); err == nil {
				t.Fatal("expected an error")
			}
			if r.token(t) != r.old {
				t.Fatal("Keep's token changed")
			}
			if len(r.s.delAuth) != 0 || len(r.hook.ev) != 0 {
				t.Fatalf("DELETE %d hook %d", len(r.s.delAuth), len(r.hook.ev))
			}
			// The old token still authenticates: the account is not locked out.
			if _, _, err := r.x.Current(context.Background(), ""); err != nil {
				t.Fatalf("old token no longer works: %v", err)
			}
		})
	}
}

// A failed DELETE of the previous token is repeated with RevokeOld; the second
// RotateSelf would only issue yet another token.
func TestExtRevokeOldAfterFailedDelete(t *testing.T) {
	r := newExtRig(t, 0)
	r.s.delFail = 1
	ctx := context.Background()
	res, err := mesh.RotateSelf(ctx, r.x, r.store, r.hook, uuid.New())
	if !errors.Is(err, rotation.ErrUnavailable) || errors.Is(err, mesh.ErrOrphaned) || len(r.hook.ev) != 0 {
		t.Fatalf("setup: %v hook %d", err, len(r.hook.ev))
	}
	if r.token(t) != r.s.current || r.s.previous == "" {
		t.Fatal("rotation should be forward-only with the previous token still alive")
	}
	if _, err := mesh.RevokeOld(ctx, r.x, r.hook, res); err != nil {
		t.Fatal(err)
	}
	if r.s.previous != "" || len(r.hook.ev) != 1 {
		t.Fatalf("previous %q hook %d", r.s.previous, len(r.hook.ev))
	}
	if _, err := mesh.RevokeOld(ctx, r.x, r.hook, res); err != nil {
		t.Fatalf("repeat: %v", err)
	}
}

// Called with the previous token, Mesh answers 409 so it cannot end itself:
// the plugin never does that because it reads the token after Activate.
func TestExtDeleteUsesCurrentTokenOnly(t *testing.T) {
	r := newExtRig(t, 0)
	if _, err := mesh.RotateSelf(context.Background(), r.x, r.store, nil, uuid.New()); err != nil {
		t.Fatal(err)
	}
	for _, a := range r.s.delAuth {
		if a == r.old {
			t.Fatal("DELETE sent with the previous token")
		}
	}
}

func TestExtBadAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"empty":          `{}`,
		"not json":       `nope`,
		"wrong prefix":   `{"extension_token":"agk_abcdef","token_length":10}`,
		"length differs": `{"extension_token":"ext_abcdef","token_length":3}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newExtRig(t, 0)
			r.s.answer = body
			if _, err := mesh.RotateSelf(context.Background(), r.x, r.store, r.hook, uuid.New()); !errors.Is(err, mesh.ErrBadAnswer) {
				t.Fatalf("got %v", err)
			}
			if r.token(t) != r.old || len(r.s.delAuth) != 0 {
				t.Fatal("state changed")
			}
		})
	}
}

func TestExtNoCapabilityIsDenied(t *testing.T) {
	r := newExtRig(t, 0)
	r.s.noCap = true
	if _, err := mesh.RotateSelf(context.Background(), r.x, r.store, r.hook, uuid.New()); !errors.Is(err, rotation.ErrDenied) {
		t.Fatalf("got %v", err)
	}
	if r.token(t) != r.old {
		t.Fatal("token changed")
	}
}

func TestExtConfigRefusals(t *testing.T) {
	src := func(context.Context) (mesh.Token, error) { return "ext_x", nil }
	acct := uuid.NewString()
	for name, c := range map[string]mesh.ExtConfig{
		"no source":   {BaseURL: "https://m.example", AccountID: acct},
		"bad account": {BaseURL: "https://m.example", AccountID: "x", TokenSource: src},
		"plain http":  {BaseURL: "http://m.example", AccountID: acct, TokenSource: src},
		"grace big":   {BaseURL: "https://m.example", AccountID: acct, TokenSource: src, GraceSeconds: 3601},
		"grace neg":   {BaseURL: "https://m.example", AccountID: acct, TokenSource: src, GraceSeconds: -1},
		"no host":     {BaseURL: "https:///x", AccountID: acct, TokenSource: src},
	} {
		if _, err := mesh.NewExtSelf(c); !errors.Is(err, mesh.ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := mesh.NewExtSelf(mesh.ExtConfig{BaseURL: "https://m.example", AccountID: acct, TokenSource: src, GraceSeconds: 3600}); err != nil {
		t.Fatalf("max grace refused: %v", err)
	}
}

// The issued token is the canary: it must not reach a log, an error, a
// printed result or the formatted rotator, on a good run and on failures.
func TestExtCanaryDoesNotSurface(t *testing.T) {
	c := canary.New()
	var out []string
	run := func(set func(*extRig)) *extRig {
		r := newExtRig(t, 0)
		r.s.nextTok = "ext_" + c.Value(0)
		set(r)
		res, err := mesh.RotateSelf(context.Background(), r.x, r.store, r.hook, uuid.New())
		out = append(out, fmt.Sprintf("%+v %v %#v %v", res, err, r.x, r.x), r.logs.String())
		return r
	}
	good := run(func(*extRig) {})
	run(func(r *extRig) { r.s.rejectNew = true })
	run(func(r *extRig) { r.s.delFail = 1 })
	run(func(r *extRig) { r.s.answer = `{"extension_token":"` + c.Value(0) + `"}` })
	if !strings.Contains(good.logs.String(), "issue") {
		t.Fatal("positive control: rotation not journaled")
	}
	if c.In(strings.Join(out, "\n")) {
		t.Fatalf("canary surfaced: %v", out)
	}
}

func TestExtSourceErrorNotForwarded(t *testing.T) {
	s := newStubExt(t, "ext_x")
	x, err := mesh.NewExtSelf(mesh.ExtConfig{BaseURL: s.srv.URL, AccountID: uuid.NewString(),
		TokenSource: func(context.Context) (mesh.Token, error) { return "", errors.New("vault says hunter2") }})
	if err != nil {
		t.Fatal(err)
	}
	_, _, cerr := x.Current(context.Background(), "")
	if !errors.Is(cerr, rotation.ErrUnavailable) || strings.Contains(cerr.Error(), "hunter2") {
		t.Fatalf("got %v", cerr)
	}
	if len(s.calls) != 0 {
		t.Fatal("a call was made without a token")
	}
}

func TestExtRedirectDoesNotCarryToken(t *testing.T) {
	var seen string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("Authorization") }))
	defer evil.Close()
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	}))
	defer hop.Close()
	x, _ := mesh.NewExtSelf(mesh.ExtConfig{BaseURL: hop.URL, AccountID: uuid.NewString(),
		TokenSource: func(context.Context) (mesh.Token, error) { return "ext_secret-ish", nil }})
	if _, _, err := x.Current(context.Background(), ""); err == nil {
		t.Fatal("redirect followed as success")
	}
	if seen != "" {
		t.Fatal("token followed the redirect")
	}
}

// After a failure past Issue the old token is only valid for the grace window
// and Mesh cannot issue the new one again: the rotation reports ErrOrphaned and
// keeps the staged value, which the operator can still activate once the old
// token has expired. Without that the account would be locked out.
func TestExtOrphanedRotationKeepsNewToken(t *testing.T) {
	ctx := context.Background()
	for name, set := range map[string]func(*extRig){
		"verify unavailable": func(r *extRig) { r.s.meFailNew = http.StatusServiceUnavailable },
		"verify rejected":    func(r *extRig) { r.s.rejectNew = true },
	} {
		t.Run(name, func(t *testing.T) {
			r := newExtRig(t, 0)
			set(r)
			res, err := mesh.RotateSelf(ctx, r.x, r.store, r.hook, uuid.New())
			if !errors.Is(err, mesh.ErrOrphaned) {
				t.Fatalf("got %v", err)
			}
			if r.token(t) != r.old {
				t.Fatal("token changed before activation")
			}
			r.s.mu.Lock()
			r.s.previous, r.s.rejectNew, r.s.meFailNew = "", false, 0 // the grace window is over
			r.s.mu.Unlock()
			if _, _, err := r.x.Current(ctx, ""); !errors.Is(err, rotation.ErrDenied) {
				t.Fatalf("old token should be dead: %v", err)
			}
			if err := r.store.Activate(ctx, res.NewKeyID); err != nil {
				t.Fatalf("the staged new token was discarded: %v", err)
			}
			if _, _, err := r.x.Current(ctx, ""); err != nil {
				t.Fatalf("the account is locked out: %v", err)
			}
		})
	}
}

// flakySink fails the first n Stage calls and then stores into the real Store.
type flakySink struct {
	mesh.Sink
	fail, calls int
}

func (f *flakySink) Stage(ctx context.Context, id string, v secret.Value) error {
	f.calls++
	if f.calls <= f.fail {
		return errors.New("transient")
	}
	return f.Sink.Stage(ctx, id, v)
}

// A Stage that fails now and then must not lose the only copy of the new
// token: the value is still intact on the retry and the rotation completes.
func TestExtStageIsRetriedBeforeTheValueIsWiped(t *testing.T) {
	defer mesh.NoStageBackoff()()
	r := newExtRig(t, 0)
	sink := &flakySink{Sink: r.store, fail: 2}
	if _, err := mesh.RotateSelf(context.Background(), r.x, sink, r.hook, uuid.New()); err != nil {
		t.Fatalf("rotation after two transient Stage failures: %v", err)
	}
	if sink.calls != 3 {
		t.Fatalf("stage calls %d", sink.calls)
	}
	if got := r.token(t); got != r.s.current || got == r.old {
		t.Fatal("Keep's token is not the newly issued one after the retried Stage")
	}
}

// spyRotator records Revoke calls and can fail them.
type spyRotator struct {
	mesh.SelfRotator
	revoked   []string
	revokeErr error
}

func (s *spyRotator) Revoke(ctx context.Context, id string) error {
	s.revoked = append(s.revoked, id)
	if s.revokeErr != nil {
		return s.revokeErr
	}
	return s.SelfRotator.Revoke(ctx, id)
}

// capSink keeps the Value handed to Stage so a test can look at it afterwards.
type capSink struct {
	*fakeSink
	v secret.Value
}

func (c *capSink) Stage(ctx context.Context, id string, v secret.Value) error {
	c.v = v
	return c.fakeSink.Stage(ctx, id, v)
}

// A Stage that cannot be completed loses the only copy of the new ext_ token.
// Mesh cannot end it and the old token dies after the grace window, so the
// caller gets ErrOrphaned with ErrSink (re-run at once). Neither Revoke nor
// Discard is called, and Mesh still accepts the old token until grace ends.
func TestExtStageFailureRevokesNew(t *testing.T) {
	defer mesh.NoStageBackoff()()
	r := newExtRig(t, 0)
	spy := &spyRotator{SelfRotator: r.x}
	sink := &capSink{fakeSink: &fakeSink{failStage: errors.New("disk")}}
	_, err := mesh.RotateSelf(context.Background(), spy, sink, r.hook, uuid.New())
	if !errors.Is(err, mesh.ErrOrphaned) || !errors.Is(err, mesh.ErrSink) {
		t.Fatalf("got %v", err)
	}
	if len(spy.revoked) != 0 {
		t.Fatalf("revoke calls: %d", len(spy.revoked))
	}
	for _, c := range sink.calls {
		if c == "discard" {
			t.Fatal("the sink's Discard was called")
		}
	}
	r.s.mu.Lock()
	prev, calls := r.s.previous, strings.Join(r.s.calls, ";")
	r.s.mu.Unlock()
	if prev != r.old {
		t.Fatal("Mesh no longer accepts the old token within the grace window")
	}
	if strings.Contains(calls, "DELETE") {
		t.Fatalf("a DELETE reached Mesh: %s", calls)
	}
	if got := r.token(t); got != r.old {
		t.Fatal("Keep's token changed although no new one was staged")
	}
	if sink.active != "" {
		t.Fatal("a new token was activated")
	}
	if !allZero(sink.v) {
		t.Fatal("the issued value was not wiped")
	}
	surfaces := err.Error() + r.logs.String()
	if strings.Contains(surfaces, r.s.current) || strings.Contains(surfaces, r.old) || strings.Contains(surfaces, "ext_") {
		t.Fatal("a token surfaced in an error or a log")
	}
}

// Even if Revoke would fail, the ext_ path never calls it: the result is the
// same ErrOrphaned+ErrSink and the revoke error is not part of it.
func TestExtStageFailureRevokeFailsOrphaned(t *testing.T) {
	defer mesh.NoStageBackoff()()
	r := newExtRig(t, 0)
	revokeErr := errors.New("revoke boom")
	spy := &spyRotator{SelfRotator: r.x, revokeErr: revokeErr}
	sink := &fakeSink{failStage: errors.New("disk")}
	_, err := mesh.RotateSelf(context.Background(), spy, sink, r.hook, uuid.New())
	if !errors.Is(err, mesh.ErrOrphaned) || !errors.Is(err, mesh.ErrSink) || errors.Is(err, revokeErr) {
		t.Fatalf("got %v", err)
	}
	if len(spy.revoked) != 0 {
		t.Fatalf("revoke calls: %d", len(spy.revoked))
	}
	if strings.Contains(err.Error()+r.logs.String(), "ext_") {
		t.Fatal("a token surfaced")
	}
}

// The agent-keys rotator can issue again, so its rollbacks are not orphans.
func TestProviderRollbackIsNotOrphaned(t *testing.T) {
	r := newSelfRig(t, "v")
	r.sink.failActivate = errors.New("x")
	if _, err := mesh.RotateSelf(context.Background(), r.p, r.sink, r.hook, uuid.New()); err == nil || errors.Is(err, mesh.ErrOrphaned) {
		t.Fatalf("got %v", err)
	}
}

// The POST rotated the token at Mesh but the answer never arrived: the new
// value is lost and the old one dies after grace. That is ErrOrphaned, not a
// plain unavailable.
func TestExtIssueLostAnswerIsOrphaned(t *testing.T) {
	r := newExtRig(t, 0)
	r.s.dropReply = true
	res, err := mesh.RotateSelf(context.Background(), r.x, r.store, r.hook, uuid.New())
	if !errors.Is(err, mesh.ErrOrphaned) || !errors.Is(err, rotation.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	r.s.mu.Lock()
	rotated := r.s.current != r.old
	r.s.mu.Unlock()
	if !rotated {
		t.Fatal("stub did not rotate: the test proves nothing")
	}
	if res.NewKeyID != "" || mesh.PendingLen(r.x) != 0 {
		t.Fatalf("res %+v pending %d", res, mesh.PendingLen(r.x))
	}
	if strings.Contains(err.Error()+r.logs.String(), "ext_") {
		t.Fatal("a token surfaced")
	}
}

// A refused POST (403) changed nothing at Mesh: not an orphan.
func TestExtIssueRefusedIsNotOrphaned(t *testing.T) {
	r := newExtRig(t, 0)
	r.s.noCap = true
	_, err := mesh.RotateSelf(context.Background(), r.x, r.store, r.hook, uuid.New())
	if err == nil || errors.Is(err, mesh.ErrOrphaned) {
		t.Fatalf("got %v", err)
	}
}

// A 200 with an unusable body also replaced the token.
func TestExtIssueBadAnswerIsOrphaned(t *testing.T) {
	r := newExtRig(t, 0)
	r.s.answer = `{"extension_token":"nope"}`
	_, err := mesh.RotateSelf(context.Background(), r.x, r.store, r.hook, uuid.New())
	if !errors.Is(err, mesh.ErrOrphaned) || !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("got %v", err)
	}
}

// After a Stage that cannot be completed the provider holds no plaintext, and
// neither Revoke nor Discard was used to get there.
func TestExtStageExhaustedDropsHeldPlaintext(t *testing.T) {
	defer mesh.NoStageBackoff()()
	r := newExtRig(t, 0)
	sink := &capSink{fakeSink: &fakeSink{failStage: errors.New("disk")}}
	_, err := mesh.RotateSelf(context.Background(), r.x, sink, r.hook, uuid.New())
	if !errors.Is(err, mesh.ErrOrphaned) {
		t.Fatalf("got %v", err)
	}
	if n := mesh.PendingLen(r.x); n != 0 {
		t.Fatalf("held tokens after exhausted Stage: %d", n)
	}
	for _, c := range sink.calls {
		if c == "discard" {
			t.Fatal("Discard was called")
		}
	}
}

// A 5xx to the POST may come after Mesh rotated the token: also an orphan.
func TestExtIssue5xxIsOrphaned(t *testing.T) {
	r := newExtRig(t, 0)
	r.s.failReply = http.StatusBadGateway
	_, err := mesh.RotateSelf(context.Background(), r.x, r.store, r.hook, uuid.New())
	if !errors.Is(err, mesh.ErrOrphaned) {
		t.Fatalf("got %v", err)
	}
}
