package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/entire-vc/evc-keep/internal/restart"
	"github.com/google/uuid"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	"github.com/entire-vc/evc-keep/pkg/provider/svctoken"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

type bootRig struct {
	store *svctoken.Store
	logs  *bytes.Buffer
	fp    func(context.Context) (fingerprint.Key, error)
}

func newBootRig(t *testing.T) *bootRig {
	t.Helper()
	store, err := svctoken.New(memory.New(nil), "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	// A fresh key per call, as the store's FingerprintKey hands out: the caller wipes it.
	return &bootRig{store: store, logs: &bytes.Buffer{},
		fp: func(context.Context) (fingerprint.Key, error) { return fingerprint.GenerateKey("testkey") }}
}

func (r *bootRig) boot(path string) error {
	return bootstrapSvcToken(context.Background(), r.store, path, r.fp, obs.New(r.logs))
}

func tokenFileMode(t *testing.T, mode os.FileMode, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "svc.token")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// The canary is the token in the bootstrap file. It must not reach the log
// (through the production logger, which has a closed key set) or an error; the
// log carries name, version, fingerprint and length, and the file stays.
func TestBootstrapCanaryDoesNotSurface(t *testing.T) {
	c := canary.New()
	tok := "ext_" + c.Value(0)
	r := newBootRig(t)
	path := tokenFileMode(t, 0o600, tok+"\n")
	if err := r.boot(path); err != nil {
		t.Fatalf("bootstrap refused a good file: %v", err)
	}
	got, err := r.store.Token(context.Background())
	if err != nil || got != tok {
		t.Fatal("positive control: the token is not sealed in the store")
	}
	line := r.logs.String()
	for _, want := range []string{"name=mesh-service-token", "version=", "fingerprint=kfp1:", fmt.Sprintf("length=%d", len(tok))} {
		if !strings.Contains(line, want) {
			t.Errorf("journal line lacks %s:\n%s", want, line)
		}
	}
	if c.In(line) {
		t.Fatalf("token reached the log:\n%s", line)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the bootstrap file was removed")
	}
}

func TestBootstrapRefusesBadFiles(t *testing.T) {
	c := canary.New()
	tok := "ext_" + c.Value(0)
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(tokenFileMode(t, 0o600, tok), link); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"group-readable":  tokenFileMode(t, 0o640, tok),
		"world-readable":  tokenFileMode(t, 0o644, tok),
		"owner-read-only": tokenFileMode(t, 0o400, tok),
		"executable":      tokenFileMode(t, 0o700, tok),
		"empty":           tokenFileMode(t, 0o600, ""),
		"blank":           tokenFileMode(t, 0o600, " \n\t\n"),
		"too large":       tokenFileMode(t, 0o600, strings.Repeat("x", 5000)),
		"directory":       t.TempDir(),
		"missing":         filepath.Join(dir, "absent"),
		"symlink":         link,
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			r := newBootRig(t)
			err := r.boot(path)
			if err == nil {
				t.Fatal("bootstrap accepted it")
			}
			if _, terr := r.store.Token(context.Background()); terr == nil {
				t.Fatal("a token was sealed from a refused file")
			}
			if c.In(err.Error() + r.logs.String()) {
				t.Fatalf("token surfaced: %v %s", err, r.logs.String())
			}
		})
	}
}

// A token that is already sealed is not replaced by the file: a restart after a
// rotation must keep the rotated token.
func TestBootstrapKeepsAnExistingToken(t *testing.T) {
	r := newBootRig(t)
	if err := r.boot(tokenFileMode(t, 0o600, "ext_first")); err != nil {
		t.Fatal(err)
	}
	if err := r.boot(tokenFileMode(t, 0o600, "ext_second")); err != nil {
		t.Fatal(err)
	}
	if tok, _ := r.store.Token(context.Background()); tok != "ext_first" {
		t.Fatal("the bootstrap file replaced an existing token")
	}
}

// Once the token is sealed the operator deletes the file (the runbook says
// so); the next start with the same configuration must not fail on it.
func TestBootstrapExistingTokenNeedsNoFile(t *testing.T) {
	r := newBootRig(t)
	p := tokenFileMode(t, 0o600, "ext_first")
	if err := r.boot(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := r.boot(p); err != nil {
		t.Fatalf("restart without the file failed: %v", err)
	}
}

// Without a bootstrap file and without a token nothing is invented: the
// scheduler's first rotation fails by class and the operator is told.
func TestBootstrapWithoutFileIsANoOp(t *testing.T) {
	r := newBootRig(t)
	if err := r.boot(""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.Token(context.Background()); err == nil {
		t.Fatal("a token appeared from nowhere")
	}
}

// The loop calls rotate on every tick, never stops on an error and logs the
// error by class: the text of a failure (here the canary) is not forwarded.
func TestRunSelfRotateLogsClassOnly(t *testing.T) {
	c := canary.New()
	var logs bytes.Buffer
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runSelfRotate(ctx, 5*time.Millisecond, func(context.Context) error {
			calls.Add(1)
			return errors.New("boom " + c.Value(0))
		}, obs.New(&logs))
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for calls.Load() < 3 {
		select {
		case <-deadline:
			t.Fatal("the loop stopped after an error")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
	if !strings.Contains(logs.String(), "error_class") {
		t.Fatalf("positive control: failure not logged: %q", logs.String())
	}
	if c.In(logs.String()) {
		t.Fatalf("error text reached the log:\n%s", logs.String())
	}
}

func TestWireSelfRotateRefusals(t *testing.T) {
	ctx := context.Background()
	if err := wireSelfRotate(ctx, config.Config{}, Options{}, nil, nil, obs.New(&bytes.Buffer{})); err != nil {
		t.Fatalf("off must be a no-op: %v", err)
	}
	cfg := config.Config{MeshSelfRotate: config.MeshSelfRotate{Enabled: true}}
	if err := wireSelfRotate(ctx, cfg, Options{}, nil, nil, obs.New(&bytes.Buffer{})); err == nil {
		t.Fatal("a build without the plugin accepted the configuration")
	}
}

// The three names svctoken seals under (main, staged, dropped) must stay out of
// reach of a caller-supplied provider_ref: the reservation in provider.ValidRef
// has to follow svcTokenName.
func TestServiceTokenNamesAreNotValidRefs(t *testing.T) {
	id := "5d1c0f43-4e0b-4f43-8a2b-2f4d9a0f77c2"
	for _, ref := range []string{
		"builtin://" + svcTokenName,
		"builtin://" + svcTokenName + "-staged-" + id,
		"builtin://" + svcTokenName + "-dropped-" + id,
	} {
		if provider.ValidRef(ref) {
			t.Errorf("%q is a valid caller ref", ref)
		}
	}
}

// A failed rotation is retried after a quarter of the interval, not a whole
// interval later, and the retries are bounded.
func TestRunSelfRotateRetriesSoon(t *testing.T) {
	var mu sync.Mutex
	var at []time.Time
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	every := 400 * time.Millisecond
	go func() {
		runSelfRotate(ctx, every, func(context.Context) error {
			mu.Lock()
			at = append(at, time.Now())
			mu.Unlock()
			return errors.New("orphaned")
		}, obs.New(&bytes.Buffer{}))
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(at)
		mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("no retry after a failed rotation")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if gap := at[1].Sub(at[0]); gap >= every/2 {
		t.Fatalf("retry came after %v, want about %v", gap, every/4)
	}
}

// A queued restart without an outcome is looked at again soon, well before the
// next interval, and is not logged as a failed rotation.
func TestRunSelfRotateChecksPendingRestartSoon(t *testing.T) {
	saved := restartCheckEvery
	restartCheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { restartCheckEvery = saved })
	var mu sync.Mutex
	var at []time.Time
	var log bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	every := 600 * time.Millisecond
	go func() {
		runSelfRotate(ctx, every, func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			at = append(at, time.Now())
			return ErrSelfRotatePending
		}, obs.New(&log))
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(at)
		mu.Unlock()
		if n >= 4 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("pending restart looked at %d times, want a check soon after each", n)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < 4; i++ {
		if gap := at[i].Sub(at[i-1]); gap >= every/2 {
			t.Fatalf("check %d came after %v, want about %v", i, gap, restartCheckEvery)
		}
	}
	if strings.Contains(log.String(), "rotation failed") {
		t.Fatalf("a pending restart was logged as a failure: %s", log.String())
	}
}

// A lane outside the queue's allowlist, or an organization that is not a UUID,
// stops the start; no lane means no queue at all.
func TestBindRestartsRefusals(t *testing.T) {
	queue := restart.NewRepo(nil)
	org := uuid.NewString()
	for name, tc := range map[string]struct {
		sr      config.MeshSelfRotate
		wantErr bool
		wantNil bool
	}{
		"no lane":                 {config.MeshSelfRotate{OrgID: org}, false, true},
		"allowed lane":            {config.MeshSelfRotate{OrgID: org, RestartLane: "Hugh"}, false, false},
		"lane not allowed":        {config.MeshSelfRotate{OrgID: org, RestartLane: "elsewhere"}, true, true},
		"organization not a UUID": {config.MeshSelfRotate{OrgID: "acme", RestartLane: "Hugh"}, true, true},
	} {
		got, err := bindRestarts(tc.sr, queue, nil, nil)
		if (err != nil) != tc.wantErr || (got == nil) != tc.wantNil {
			t.Errorf("%s: restarts=%v err=%v", name, got, err)
		}
	}
}

// sealOnlyOptions is a plugin build whose rotation counts every call: seal-only
// must build no rotation and run none.
func sealOnlyOptions(built, rotated *atomic.Int32) Options {
	return Options{
		SelfRotate: func(config.MeshSelfRotate, SelfRotateStore, SelfRotateRestarts, *slog.Logger) (func(context.Context) error, error) {
			built.Add(1)
			return func(context.Context) error { rotated.Add(1); return nil }, nil
		},
		SelfRotateEvery: time.Millisecond,
	}
}

// Seal-only seals the bootstrap token (name, version, fingerprint and length
// in the log, the value nowhere) and never builds or runs a rotation, so
// nothing calls Mesh. A second start over the sealed record is a no-op: no
// new version, no second journal line.
func TestSealOnlySealsAndNeverRotates(t *testing.T) {
	c := canary.New()
	tok := "ext_" + c.Value(0)
	r := newBootRig(t)
	path := tokenFileMode(t, 0o600, tok+"\n")
	sr := config.MeshSelfRotate{SealOnly: true, OrgID: "5d1c0f43-4e0b-4f43-8a2b-2f4d9a0f77c2", BootstrapFile: path}
	var built, rotated atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := func() error {
		return startSelfRotate(ctx, sr, sealOnlyOptions(&built, &rotated), r.store, nil, r.fp, obs.New(r.logs))
	}
	if err := start(); err != nil {
		t.Fatalf("seal-only refused a good file: %v", err)
	}
	got, err := r.store.Token(ctx)
	if err != nil || got != tok {
		t.Fatal("positive control: the token is not sealed in the store")
	}
	first := r.logs.String()
	for _, want := range []string{"name=mesh-service-token", "version=", "fingerprint=kfp1:", fmt.Sprintf("length=%d", len(tok)), "seal-only"} {
		if !strings.Contains(first, want) {
			t.Errorf("journal lacks %s:\n%s", want, first)
		}
	}
	if err := start(); err != nil {
		t.Fatalf("second seal-only start refused: %v", err)
	}
	if n := strings.Count(r.logs.String(), "sealed from bootstrap file"); n != 1 {
		t.Fatalf("second start sealed again: %d journal lines", n)
	}
	// Ticks of SelfRotateEvery would have fired many times by now.
	time.Sleep(50 * time.Millisecond)
	if built.Load() != 0 || rotated.Load() != 0 {
		t.Fatalf("seal-only reached the Mesh plugin: built=%d rotated=%d", built.Load(), rotated.Load())
	}
	if c.In(r.logs.String()) {
		t.Fatalf("token reached the log:\n%s", r.logs.String())
	}

	// Positive control for the counters: the same store with rotation on
	// builds the rotation and runs it.
	on := sr
	on.SealOnly, on.Enabled = false, true
	if err := startSelfRotate(ctx, on, sealOnlyOptions(&built, &rotated), r.store, nil, r.fp, obs.New(r.logs)); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for rotated.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("positive control: rotation on never ran")
		case <-time.After(time.Millisecond):
		}
	}
	if built.Load() != 1 {
		t.Fatalf("positive control: rotation built %d times", built.Load())
	}
}

// A refused bootstrap file in seal-only stops the start without the value.
func TestSealOnlyRefusedFileStopsTheStart(t *testing.T) {
	c := canary.New()
	r := newBootRig(t)
	sr := config.MeshSelfRotate{SealOnly: true, BootstrapFile: tokenFileMode(t, 0o644, "ext_"+c.Value(0))}
	var built, rotated atomic.Int32
	err := startSelfRotate(context.Background(), sr, sealOnlyOptions(&built, &rotated), r.store, nil, r.fp, obs.New(r.logs))
	if err == nil {
		t.Fatal("seal-only accepted a group-readable file")
	}
	if c.In(err.Error() + r.logs.String()) {
		t.Fatalf("token surfaced: %v %s", err, r.logs.String())
	}
	if built.Load() != 0 {
		t.Fatal("seal-only reached the Mesh plugin")
	}
}

// The core build has no plugin: seal-only stops its start like rotation does.
func TestWireSealOnlyNeedsThePlugin(t *testing.T) {
	cfg := config.Config{MeshSelfRotate: config.MeshSelfRotate{SealOnly: true}}
	err := wireSelfRotate(context.Background(), cfg, Options{}, nil, nil, obs.New(&bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "no Mesh plugin") {
		t.Fatalf("a build without the plugin accepted seal-only: %v", err)
	}
}

// The store the server builds must reach the builtin provider's Erase, or each
// rotation leaves a sealed staged copy of the live token behind.
func TestSelfRotateStoreErasesStagedCopies(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 1
	local, err := builtin.NewLocal(nil, "k", raw, nil, func(builtin.KeyEvent) {})
	if err != nil {
		t.Fatal(err)
	}
	store, err := selfRotateStore(local.Provider(uuid.NewString(), "", "", ""), obs.New(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	if !store.CanErase() {
		t.Fatal("the self-rotation store cannot erase staged copies")
	}
	plain, err := svctoken.New(memory.New(nil), svcTokenName)
	if err != nil {
		t.Fatal(err)
	}
	if plain.CanErase() {
		t.Fatal("positive control: a provider without Erase is reported as erasing")
	}
}

// failingEraser is a provider whose Erase fails with the canary in its text.
type failingEraser struct {
	*memory.Provider
	err error
}

func (f failingEraser) Erase(context.Context, provider.Ref) error { return f.err }

// A staged copy left behind is logged as a class: neither the token nor the
// provider's error text reaches the log.
func TestStagedLeftLogsClassOnly(t *testing.T) {
	c := canary.New()
	store, err := svctoken.New(failingEraser{memory.New(nil), fmt.Errorf("%w: %s", provider.ErrUnavailable, c.Value(1))}, svcTokenName)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logStagedLeft(store, obs.New(&logs))
	ctx := context.Background()
	id := uuid.NewString()
	if err := store.Stage(ctx, id, secret.New([]byte(c.Value(0)))); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(ctx, id); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "staged_cleanup") {
		t.Fatalf("positive control: no staged_cleanup line in %q", logs.String())
	}
	if c.In(logs.String()) {
		t.Fatal("canary surfaced in the staged-cleanup log")
	}
}
