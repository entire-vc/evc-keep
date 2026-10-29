package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func actorCfg() config.Config {
	return config.Config{
		MeshExtension:  true,
		MeshGate:       config.MeshGate{Enabled: true, URL: "https://mesh.invalid", TokenFile: "/nonexistent"},
		MeshSelfRotate: config.MeshSelfRotate{Enabled: true, AccountID: "00000000-0000-4000-8000-000000000001"},
	}
}

func actorOpts(err error, calls *int) Options {
	return Options{
		SelfRotate: func(config.MeshSelfRotate, SelfRotateStore, SelfRotateRestarts, *slog.Logger) (func(context.Context) error, error) {
			return nil, nil
		},
		SelfRotateActor: func(context.Context, config.MeshGate, GateTokenSource, string, *slog.Logger) error {
			*calls++
			return err
		},
	}
}

// The plugin's same-actor answer stops the start with the class text; any
// other refusal stops it without the plugin's text, which may carry anything.
func TestSelfRotateActorMapsPluginAnswer(t *testing.T) {
	c := canary.New()
	var calls int
	var logs bytes.Buffer
	err := checkSelfRotateActor(context.Background(), actorCfg(), actorOpts(errors.Join(ErrSelfRotateSameActor, errors.New(c.Value(0))), &calls), nil, nil, obs.New(&logs))
	if !errors.Is(err, ErrSelfRotateSameActor) || err.Error() != "self-rotation account is the gate's actor" {
		t.Fatalf("same actor: %v", err)
	}
	if !strings.Contains(logs.String(), `"error_class":"same_actor"`) {
		t.Fatalf("no class in the log: %s", logs.String())
	}
	err2 := checkSelfRotateActor(context.Background(), actorCfg(), actorOpts(errors.New(c.Value(1)), &calls), nil, nil, obs.New(&logs))
	if err2 == nil || errors.Is(err2, ErrSelfRotateSameActor) {
		t.Fatalf("other refusal: %v", err2)
	}
	if calls != 2 {
		t.Fatalf("check called %d times, want 2", calls)
	}
	if c.In(err.Error()) || c.In(err2.Error()) || c.In(logs.String()) {
		t.Fatalf("plugin text forwarded: %q %q %s", err, err2, logs.String())
	}
	if err := checkSelfRotateActor(context.Background(), actorCfg(), actorOpts(nil, &calls), nil, nil, obs.New(&logs)); err != nil {
		t.Fatalf("different actors: %v", err)
	}
}

// The check runs only when the gate is on and the token rotates; a plugin
// build without the check is refused rather than skipped.
func TestSelfRotateActorWhenItRuns(t *testing.T) {
	off := []func(*config.Config){
		func(c *config.Config) { c.MeshExtension = false },
		func(c *config.Config) { c.MeshGate.Enabled = false },
		func(c *config.Config) { c.MeshSelfRotate.Enabled = false },
		func(c *config.Config) { c.MeshSelfRotate.SealOnly = true },
	}
	for i, f := range off {
		cfg := actorCfg()
		f(&cfg)
		var calls int
		if err := checkSelfRotateActor(context.Background(), cfg, actorOpts(ErrSelfRotateSameActor, &calls), nil, nil, obs.New(&bytes.Buffer{})); err != nil || calls != 0 {
			t.Fatalf("case %d: err=%v calls=%d, want no check", i, err, calls)
		}
	}
	var calls int
	opts := actorOpts(nil, &calls)
	opts.SelfRotateActor = nil
	if err := checkSelfRotateActor(context.Background(), actorCfg(), opts, nil, nil, obs.New(&bytes.Buffer{})); err == nil {
		t.Fatal("a plugin build without the actor check started")
	}
	cfg := actorCfg()
	cfg.MeshGate.TokenFile, cfg.MeshGate.WorkspaceID = "", "not-a-uuid"
	if err := checkSelfRotateActor(context.Background(), cfg, actorOpts(nil, &calls), nil, nil, obs.New(&bytes.Buffer{})); err == nil || calls != 0 {
		t.Fatalf("unreachable vault source: err=%v calls=%d", err, calls)
	}
}
