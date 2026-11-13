package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/entire-vc/evc-keep/cmd/keep-server/app"
	"github.com/entire-vc/evc-keep/pkg/rotation"
	mesh "github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

// Settings of the Mesh agent-key rotation. All three or none: a part set is a
// refused start, so a typo does not silently leave a secret on generated values.
//
//	KEEP_MESH_ROTATE_URL         base address of the Mesh whose agent keys are rotated
//	KEEP_MESH_ROTATE_TOKEN_FILE  file (mode 0600) with the service token (right agent_key:rotate)
//	KEEP_MESH_ROTATE_BINDINGS    JSON file {"<secret id>": "<agent id>"}, ids only
const (
	envRotateURL      = "KEEP_MESH_ROTATE_URL"
	envRotateToken    = "KEEP_MESH_ROTATE_TOKEN_FILE" //nolint:gosec // G101: a variable name, not a credential
	envRotateBindings = "KEEP_MESH_ROTATE_BINDINGS"
	maxBindingsFile   = 1 << 20
)

var errBindings = errors.New("mesh rotation bindings unavailable")

// newRotators is app.Options.Rotators: a secret named in the bindings file is
// rotated through the Mesh agent-keys API, any other keeps the generator. The
// file is read on every call, like the token, so a changed binding applies to
// the next run without a restart.
func newRotators(logger *slog.Logger) (app.RotatorSource, error) {
	url, tok, bind := os.Getenv(envRotateURL), os.Getenv(envRotateToken), os.Getenv(envRotateBindings)
	if url == "" && tok == "" && bind == "" {
		return nil, nil
	}
	if url == "" || tok == "" || bind == "" {
		return nil, errors.New("mesh rotation: set all of the URL, token file and bindings file, or none")
	}
	// A configuration that cannot work stops the start, not the first rotation.
	if !filepath.IsAbs(tok) || !filepath.IsAbs(bind) {
		return nil, errors.New("mesh rotation: the token and bindings files must be absolute paths")
	}
	if _, err := tokenFromFile(tok)(context.Background()); err != nil {
		return nil, err
	}
	if _, err := mesh.New(mesh.Config{BaseURL: url, AgentID: uuid.NewString(), TokenSource: tokenFromFile(tok)}); err != nil {
		return nil, err
	}
	if _, err := readBindings(bind); err != nil {
		return nil, err
	}
	src := tokenFromFile(tok)
	return func(ctx context.Context, _, secretID uuid.UUID) (rotation.RotationProvider, bool, error) {
		m, err := readBindings(bind)
		if err != nil {
			return nil, false, err
		}
		agent, ok := m[secretID.String()]
		if !ok {
			return nil, false, nil
		}
		p, err := mesh.New(mesh.Config{BaseURL: url, AgentID: agent, TokenSource: src, Log: logger})
		if err != nil {
			return nil, false, err
		}
		return p, true, nil
	}, nil
}

// readBindings returns secret id -> agent id. Both are canonical lowercase
// UUIDs; anything else, a second document or an unknown field refuses the file.
func readBindings(path string) (map[string]string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the operator's own KEEP_MESH_ROTATE_BINDINGS.
	if err != nil {
		return nil, errBindings
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	// Whoever can write this file decides whose agent key is issued for a
	// secret: only the process's own user, and nobody else with write access.
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 || !ownedByUs(fi) {
		return nil, errBindings
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBindingsFile+1))
	if err != nil || len(raw) > maxBindingsFile {
		return nil, errBindings
	}
	var m map[string]string
	if json.Unmarshal(raw, &m) != nil {
		return nil, errBindings
	}
	// An agent holds one secret: two secrets on one agent would let the
	// rotation of one revoke the key the other lays out.
	seen := map[string]bool{}
	for s, a := range m {
		if !rotation.ValidKeyID(s) || !rotation.ValidKeyID(a) || seen[a] {
			return nil, errBindings
		}
		seen[a] = true
	}
	return m, nil
}

// ownedByUs: the file belongs to the user the server runs as.
func ownedByUs(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
