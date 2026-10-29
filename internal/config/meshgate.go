package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
)

// DefaultMeshSweepInterval is how often lapsed gate cards are cancelled when
// KEEP_MESH_SWEEP_INTERVAL is not set.
const DefaultMeshSweepInterval = time.Minute

// MeshGate is where confirmation cards are created. Only names and paths are
// held: the token itself stays sealed in the installation of WorkspaceID, or
// in TokenFile, and is read on each call, never here. No error or log line built from this carries a value.
type MeshGate struct {
	// Enabled is true only when every KEEP_MESH_* gate variable is set.
	Enabled bool
	// ProjectID is KEEP_MESH_PROJECT_ID, the Mesh project the cards go to.
	ProjectID string
	// URL is KEEP_MESH_URL, the base address of Mesh.
	URL string
	// CancelStatusID is KEEP_MESH_CANCEL_STATUS_ID, the project's cancelled
	// status, used to close a card whose request lapsed.
	CancelStatusID string
	// TokenFile is KEEP_MESH_TOKEN_FILE, a path to a file (mode 0600, not
	// empty) holding the extension actor's token. Empty when WorkspaceID is set.
	TokenFile string
	// WorkspaceID is KEEP_MESH_WORKSPACE_ID, the Mesh workspace whose
	// installation holds the actor token sealed in Keep's vault. Exactly one
	// of TokenFile and WorkspaceID is set.
	WorkspaceID string
	// SweepEvery is KEEP_MESH_SWEEP_INTERVAL; the default is one minute.
	SweepEvery time.Duration
}

// meshGateFromEnv reads the gate settings. None set means the gate is off and
// Keep runs without Mesh; a part set, or any bad one, is an error that names
// the variable and never its value.
func meshGateFromEnv(extension bool) (MeshGate, error) {
	g := MeshGate{
		ProjectID:      os.Getenv("KEEP_MESH_PROJECT_ID"),
		URL:            os.Getenv("KEEP_MESH_URL"),
		CancelStatusID: os.Getenv("KEEP_MESH_CANCEL_STATUS_ID"),
		TokenFile:      os.Getenv("KEEP_MESH_TOKEN_FILE"),
		WorkspaceID:    os.Getenv("KEEP_MESH_WORKSPACE_ID"),
	}
	interval := os.Getenv("KEEP_MESH_SWEEP_INTERVAL")
	if g.ProjectID == "" && g.URL == "" && g.CancelStatusID == "" && g.TokenFile == "" && g.WorkspaceID == "" && interval == "" {
		return MeshGate{}, nil
	}
	for _, v := range []struct{ name, val string }{
		{"KEEP_MESH_PROJECT_ID", g.ProjectID}, {"KEEP_MESH_URL", g.URL},
		{"KEEP_MESH_CANCEL_STATUS_ID", g.CancelStatusID},
	} {
		if v.val == "" {
			return MeshGate{}, fmt.Errorf("%s is required when any Mesh gate variable is set", v.name)
		}
	}
	switch {
	case g.TokenFile == "" && g.WorkspaceID == "":
		return MeshGate{}, errors.New("KEEP_MESH_TOKEN_FILE or KEEP_MESH_WORKSPACE_ID is required when any Mesh gate variable is set")
	case g.TokenFile != "" && g.WorkspaceID != "":
		return MeshGate{}, errors.New("KEEP_MESH_TOKEN_FILE and KEEP_MESH_WORKSPACE_ID exclude each other: set one")
	}
	if !extension {
		return MeshGate{}, errors.New("the Mesh gate (KEEP_MESH_PROJECT_ID) needs KEEP_MESH_EXTENSION=1: answers arrive on the extension routes")
	}
	if !canonicalUUID(g.ProjectID) {
		return MeshGate{}, errors.New("KEEP_MESH_PROJECT_ID must be a UUID")
	}
	if !canonicalUUID(g.CancelStatusID) {
		return MeshGate{}, errors.New("KEEP_MESH_CANCEL_STATUS_ID must be a UUID")
	}
	if u, err := url.Parse(g.URL); err != nil || u.Host == "" || u.Hostname() == "" {
		return MeshGate{}, errors.New("KEEP_MESH_URL must be an absolute URL")
	}
	if g.WorkspaceID != "" && !canonicalUUID(g.WorkspaceID) {
		return MeshGate{}, errors.New("KEEP_MESH_WORKSPACE_ID must be a UUID")
	}
	if g.TokenFile != "" {
		if err := checkTokenFile(g.TokenFile); err != nil {
			return MeshGate{}, err
		}
	}
	g.SweepEvery = DefaultMeshSweepInterval
	if interval != "" {
		d, err := time.ParseDuration(interval)
		if err != nil || d < time.Second {
			return MeshGate{}, errors.New("KEEP_MESH_SWEEP_INTERVAL must be a duration of at least 1s")
		}
		g.SweepEvery = d
	}
	g.Enabled = true
	return g, nil
}

func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

// checkTokenFile requires a regular, non-empty file of mode 0600. Errors name the path only; the content is not read.
func checkTokenFile(path string) error {
	fi, err := os.Stat(path) //nolint:gosec // G703: the operator's own KEEP_MESH_TOKEN_FILE, checked here before the plugin reads it.
	switch {
	case err != nil:
		return fmt.Errorf("KEEP_MESH_TOKEN_FILE %s: cannot be read", path)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("KEEP_MESH_TOKEN_FILE %s: not a regular file", path)
	case fi.Mode().Perm() != 0o600:
		return fmt.Errorf("KEEP_MESH_TOKEN_FILE %s: mode must be 0600", path)
	case fi.Size() == 0:
		return fmt.Errorf("KEEP_MESH_TOKEN_FILE %s: file is empty", path)
	}
	return nil
}
