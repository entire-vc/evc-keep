package config

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// DefaultMeshSelfRotateInterval is how often the service token is rotated when
// KEEP_MESH_SELF_ROTATE_INTERVAL is not set.
const DefaultMeshSelfRotateInterval = 24 * time.Hour

// MeshSelfRotate is the background rotation of Keep's own Mesh service token
// (the ext_ account the Mesh plugin calls Mesh with). It is off unless
// KEEP_MESH_SELF_ROTATE=1. Only names and paths are held: the token lives
// sealed in Keep's store and the bootstrap file is read once at start.
type MeshSelfRotate struct {
	Enabled bool
	// SealOnly is a bootstrap file and an organisation without
	// KEEP_MESH_SELF_ROTATE: the token is sealed at start and never rotated.
	SealOnly bool
	// URL is KEEP_MESH_SELF_ROTATE_URL, the base address of Mesh.
	URL string
	// AccountID is KEEP_MESH_SELF_ROTATE_ACCOUNT_ID, the actor id of the account.
	AccountID string
	// OrgID is KEEP_MESH_SELF_ROTATE_ORG_ID, the organisation whose store seals the token.
	OrgID string
	// Interval is KEEP_MESH_SELF_ROTATE_INTERVAL; the default is 24h.
	Interval time.Duration
	// HookPath is KEEP_MESH_SELF_ROTATE_HOOK, an absolute path to the program
	// run after a rotation. It gets no arguments and no token.
	HookPath string
	// RestartLane is KEEP_MESH_SELF_ROTATE_RESTART_LANE: the lane whose poller
	// restarts it after a rotation. Set, the restart goes through the queue
	// (the old key is revoked only after the poller acknowledges it); the
	// lane must be on the queue's allowlist. Empty means no queue.
	RestartLane string
	// BootstrapFile is KEEP_MESH_SVC_BOOTSTRAP_FILE: the first token, sealed
	// when the store holds none. Mode and content are checked when it is read.
	BootstrapFile string
}

// meshSelfRotateFromEnv reads the self-rotation settings. Errors name the
// variable and never its value.
func meshSelfRotateFromEnv(extension bool) (MeshSelfRotate, error) {
	g := MeshSelfRotate{
		URL:           os.Getenv("KEEP_MESH_SELF_ROTATE_URL"),
		AccountID:     os.Getenv("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID"),
		OrgID:         os.Getenv("KEEP_MESH_SELF_ROTATE_ORG_ID"),
		HookPath:      os.Getenv("KEEP_MESH_SELF_ROTATE_HOOK"),
		RestartLane:   os.Getenv("KEEP_MESH_SELF_ROTATE_RESTART_LANE"),
		BootstrapFile: os.Getenv("KEEP_MESH_SVC_BOOTSTRAP_FILE"),
	}
	interval := os.Getenv("KEEP_MESH_SELF_ROTATE_INTERVAL")
	on := os.Getenv("KEEP_MESH_SELF_ROTATE")
	if on == "" && g.URL == "" && g.AccountID == "" && g.OrgID == "" && g.HookPath == "" && g.RestartLane == "" && g.BootstrapFile == "" && interval == "" {
		return MeshSelfRotate{}, nil
	}
	if on == "" && g.BootstrapFile != "" {
		return sealOnlyFromEnv(g, interval, extension)
	}
	if on != "1" {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_* need KEEP_MESH_SELF_ROTATE=1; without it only KEEP_MESH_SVC_BOOTSTRAP_FILE with KEEP_MESH_SELF_ROTATE_ORG_ID (seal-only)")
	}
	if !extension {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE=1 needs KEEP_MESH_EXTENSION=1")
	}
	if u, err := url.Parse(g.URL); err != nil || u.Host == "" || u.Hostname() == "" {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_URL must be an absolute URL")
	}
	if !canonicalUUID(g.AccountID) {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID must be a UUID")
	}
	if !canonicalUUID(g.OrgID) {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_ORG_ID must be a UUID")
	}
	if g.HookPath != "" && !filepath.IsAbs(g.HookPath) {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_HOOK must be an absolute path")
	}
	if g.RestartLane != "" && g.HookPath != "" {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_RESTART_LANE and KEEP_MESH_SELF_ROTATE_HOOK are alternatives, set one")
	}
	if g.BootstrapFile != "" && !filepath.IsAbs(g.BootstrapFile) {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SVC_BOOTSTRAP_FILE must be an absolute path")
	}
	g.Interval = DefaultMeshSelfRotateInterval
	if interval != "" {
		d, err := time.ParseDuration(interval)
		if err != nil || d < time.Second {
			return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_INTERVAL must be a duration of at least 1s")
		}
		g.Interval = d
	}
	g.Enabled = true
	return g, nil
}

// sealOnlyFromEnv checks the seal-only shape: the bootstrap file and the
// organisation are required, URL and account are checked when present (they
// may wait there for rotation), and a hook or an interval is refused because
// nothing would run them; so is a restart lane, nothing would enqueue for it.
func sealOnlyFromEnv(g MeshSelfRotate, interval string, extension bool) (MeshSelfRotate, error) {
	if !extension {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SVC_BOOTSTRAP_FILE needs KEEP_MESH_EXTENSION=1")
	}
	if g.HookPath != "" || interval != "" {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_HOOK and KEEP_MESH_SELF_ROTATE_INTERVAL need KEEP_MESH_SELF_ROTATE=1")
	}
	if g.RestartLane != "" {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_RESTART_LANE needs KEEP_MESH_SELF_ROTATE=1")
	}
	if g.URL != "" {
		if u, err := url.Parse(g.URL); err != nil || u.Host == "" || u.Hostname() == "" {
			return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_URL must be an absolute URL")
		}
	}
	if g.AccountID != "" && !canonicalUUID(g.AccountID) {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID must be a UUID")
	}
	if !canonicalUUID(g.OrgID) {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SELF_ROTATE_ORG_ID must be a UUID")
	}
	if !filepath.IsAbs(g.BootstrapFile) {
		return MeshSelfRotate{}, errors.New("KEEP_MESH_SVC_BOOTSTRAP_FILE must be an absolute path")
	}
	g.SealOnly = true
	return g, nil
}
