package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"syscall"

	"github.com/entire-vc/evc-keep/cmd/keep-server/app"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	mesh "github.com/entire-vc/evc-keep/plugins/mesh"
)

// maxTokenFile bounds what is read from the token file.
const maxTokenFile = 4096

// errToken carries no text of the file or the path: the plugin forwards none
// of it anyway, and a caller must not be able to print it by accident.
var errToken = errors.New("mesh gate token unavailable")

// newCards builds the Mesh side of the confirmation gate from the checked
// configuration. The token is not read here: it is asked for on every call,
// from tokens (the actor token sealed at install) or, without one, from the
// token file, so a rotated token takes effect without a restart.
func newCards(cfg config.MeshGate, tokens app.GateTokenSource, logger *slog.Logger) (gatecard.Cards, error) {
	src := tokenFromFile(cfg.TokenFile)
	if tokens != nil {
		src = tokenFromSource(tokens)
	}
	g, err := mesh.NewGates(mesh.GateConfig{
		BaseURL:        cfg.URL,
		ProjectID:      cfg.ProjectID,
		CancelStatusID: cfg.CancelStatusID,
		TokenSource:    src,
		Log:            logger,
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// tokenFromSource asks the core for the actor token on each call and keeps
// nothing: the core unseals it anew every time. Its error text is not kept.
func tokenFromSource(tokens app.GateTokenSource) mesh.TokenSource {
	return func(ctx context.Context) (mesh.Token, error) {
		tok, err := tokens.Token(ctx)
		if err != nil || tok == "" {
			return "", errToken
		}
		return mesh.Token(tok), nil
	}
}

// tokenFromFile returns the current token of path on each call. The file must
// still be a regular, non-empty file of mode 0600; the check
// is made on the open descriptor, not on the path.
func tokenFromFile(path string) mesh.TokenSource {
	return func(context.Context) (mesh.Token, error) {
		// O_NONBLOCK: a FIFO put in the path later must fail the check below, not hang the approval that is waiting for a card.
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the operator's own KEEP_MESH_TOKEN_FILE, checked at start.
		if err != nil {
			return "", errToken
		}
		defer func() { _ = f.Close() }()
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			return "", errToken
		}
		raw, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
		if err != nil || len(raw) > maxTokenFile {
			clear(raw)
			return "", errToken
		}
		tok := mesh.Token(bytes.TrimSpace(raw))
		clear(raw)
		if tok == "" {
			return "", errToken
		}
		return tok, nil
	}
}

// checkSelfRotateActor refuses a self-rotation account that is the gate's own
// actor. The gate's token comes from the same source the cards use and goes
// only to the gate's Mesh.
func checkSelfRotateActor(ctx context.Context, gate config.MeshGate, tokens app.GateTokenSource, account string, logger *slog.Logger) error {
	src := tokenFromFile(gate.TokenFile)
	if tokens != nil {
		src = tokenFromSource(tokens)
	}
	err := mesh.CheckSelfRotateActor(ctx, mesh.ActorCheck{BaseURL: gate.URL, AccountID: account, Gate: src, Log: logger})
	if errors.Is(err, mesh.ErrSameActor) {
		return app.ErrSelfRotateSameActor
	}
	return err
}

// newSelfRotate builds one rotation of the service token over its sealed store.
// A queued restart without an outcome is told to the loop as
// app.ErrSelfRotatePending, so the loop looks again within the grace window.
func newSelfRotate(cfg config.MeshSelfRotate, store app.SelfRotateStore, restarts app.SelfRotateRestarts, logger *slog.Logger) (func(context.Context) error, error) {
	rotate, err := mesh.NewSelfRotation(mesh.SelfRotateConfig{
		BaseURL:   cfg.URL,
		AccountID: cfg.AccountID,
		Store:     store,
		HookPath:  cfg.HookPath,
		Restarts:  restarts,
		Log:       logger,
	})
	if err != nil {
		return nil, err
	}
	return pendingForApp(rotate), nil
}

// pendingForApp maps the plugin's pending restart onto the core loop's sentinel;
// any other result passes through unchanged.
func pendingForApp(rotate func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		err := rotate(ctx)
		if errors.Is(err, mesh.ErrRestartPending) {
			return app.ErrSelfRotatePending
		}
		return err
	}
}
