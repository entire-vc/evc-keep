package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

const (
	gateProject = "0b2f6a54-6f1d-4a0e-9a54-1f0f6c3b8a11"
	gateCancel  = "5d1c0f43-4e0b-4f43-8a2b-2f4d9a0f77c2"
	// gateWorkspace is the Mesh workspace whose installation holds the token.
	gateWorkspace = "9c4e2b71-3d5a-4f8e-b1c6-7a2d0e9f4b35"
)

func gateEnv(t *testing.T, tokenFile string) {
	t.Helper()
	t.Setenv("KEEP_DATABASE_URL", "postgres://synthetic-test-only@127.0.0.1:1/keep")
	t.Setenv("KEEP_MESH_EXTENSION", "1")
	t.Setenv("KEEP_MESH_PROJECT_ID", gateProject)
	t.Setenv("KEEP_MESH_URL", "https://mesh.example.test")
	t.Setenv("KEEP_MESH_CANCEL_STATUS_ID", gateCancel)
	t.Setenv("KEEP_MESH_TOKEN_FILE", tokenFile)
	t.Setenv("KEEP_MESH_WORKSPACE_ID", "")
	t.Setenv("KEEP_MESH_SWEEP_INTERVAL", "")
}

func tokenFile(t *testing.T, mode os.FileMode, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mesh.token")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMeshGateOffWithoutAnyVariable(t *testing.T) {
	gateEnv(t, "")
	for _, k := range []string{"KEEP_MESH_PROJECT_ID", "KEEP_MESH_URL", "KEEP_MESH_CANCEL_STATUS_ID", "KEEP_MESH_TOKEN_FILE"} {
		t.Setenv(k, "")
	}
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("no Mesh gate variable must not fail the start: %v", err)
	}
	if cfg.MeshGate.Enabled {
		t.Fatal("gate enabled without configuration")
	}
}

func TestMeshGateFullConfigAndDefaultInterval(t *testing.T) {
	gateEnv(t, tokenFile(t, 0o600, "tok"))
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.MeshGate
	if !g.Enabled || g.ProjectID != gateProject || g.CancelStatusID != gateCancel || g.URL != "https://mesh.example.test" {
		t.Fatalf("gate config = %+v", g)
	}
	if g.SweepEvery != time.Minute {
		t.Fatalf("default sweep interval = %v, want 1m", g.SweepEvery)
	}
	t.Setenv("KEEP_MESH_SWEEP_INTERVAL", "30s")
	if cfg, err = FromEnv(); err != nil || cfg.MeshGate.SweepEvery != 30*time.Second {
		t.Fatalf("interval 30s: %v, %v", cfg.MeshGate.SweepEvery, err)
	}
}

// A part of the variables, or a bad one, stops the start with the NAMES of the
// variables and never their values.
func TestMeshGatePartialOrBadConfigFailsWithoutValues(t *testing.T) {
	c := canary.New()
	good := tokenFile(t, 0o600, "tok")
	cases := map[string]func(t *testing.T){
		"project without url":        func(t *testing.T) { t.Setenv("KEEP_MESH_URL", "") },
		"project without token":      func(t *testing.T) { t.Setenv("KEEP_MESH_TOKEN_FILE", "") },
		"project without cancel":     func(t *testing.T) { t.Setenv("KEEP_MESH_CANCEL_STATUS_ID", "") },
		"url without project":        func(t *testing.T) { t.Setenv("KEEP_MESH_PROJECT_ID", "") },
		"interval alone":             func(t *testing.T) { clearGate(t); t.Setenv("KEEP_MESH_SWEEP_INTERVAL", "1m") },
		"project not uuid":           func(t *testing.T) { t.Setenv("KEEP_MESH_PROJECT_ID", "not-a-uuid-"+c.Value(0)) },
		"cancel not uuid":            func(t *testing.T) { t.Setenv("KEEP_MESH_CANCEL_STATUS_ID", "nope-"+c.Value(0)) },
		"interval not a duration":    func(t *testing.T) { t.Setenv("KEEP_MESH_SWEEP_INTERVAL", "soon-"+c.Value(0)) },
		"interval below a second":    func(t *testing.T) { t.Setenv("KEEP_MESH_SWEEP_INTERVAL", "10ms") },
		"url without host":           func(t *testing.T) { t.Setenv("KEEP_MESH_URL", "https://:"+c.Value(0)) },
		"url with empty host":        func(t *testing.T) { t.Setenv("KEEP_MESH_URL", "https:///"+c.Value(0)) },
		"url with a port only":       func(t *testing.T) { t.Setenv("KEEP_MESH_URL", "https://:8080/mesh") },
		"url is a path":              func(t *testing.T) { t.Setenv("KEEP_MESH_URL", "/mesh/"+c.Value(0)) },
		"token file missing":         func(t *testing.T) { t.Setenv("KEEP_MESH_TOKEN_FILE", filepath.Join(t.TempDir(), "absent")) },
		"token file group-readable":  func(t *testing.T) { t.Setenv("KEEP_MESH_TOKEN_FILE", tokenFile(t, 0o640, "tok")) },
		"token file world-readable":  func(t *testing.T) { t.Setenv("KEEP_MESH_TOKEN_FILE", tokenFile(t, 0o644, "tok")) },
		"token file owner-read-only": func(t *testing.T) { t.Setenv("KEEP_MESH_TOKEN_FILE", tokenFile(t, 0o400, "tok")) },
		"token file owner-exec":      func(t *testing.T) { t.Setenv("KEEP_MESH_TOKEN_FILE", tokenFile(t, 0o700, "tok")) },
		"token file empty":           func(t *testing.T) { t.Setenv("KEEP_MESH_TOKEN_FILE", tokenFile(t, 0o600, "")) },
		"token file is a directory":  func(t *testing.T) { t.Setenv("KEEP_MESH_TOKEN_FILE", t.TempDir()) },
		"extension routes off":       func(t *testing.T) { t.Setenv("KEEP_MESH_EXTENSION", "") },
		"file and workspace both":    func(t *testing.T) { t.Setenv("KEEP_MESH_WORKSPACE_ID", gateWorkspace) },
		"workspace not uuid": func(t *testing.T) {
			t.Setenv("KEEP_MESH_TOKEN_FILE", "")
			t.Setenv("KEEP_MESH_WORKSPACE_ID", "ws-"+c.Value(0))
		},
		"workspace not canonical": func(t *testing.T) {
			t.Setenv("KEEP_MESH_TOKEN_FILE", "")
			t.Setenv("KEEP_MESH_WORKSPACE_ID", strings.ToUpper(gateWorkspace))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			gateEnv(t, good)
			mutate(t)
			_, err := FromEnv()
			if err == nil {
				t.Fatal("start was allowed")
			}
			if !strings.Contains(err.Error(), "KEEP_MESH_") {
				t.Fatalf("error does not name the variable: %v", err)
			}
			for _, secret := range []string{gateProject, gateCancel, gateWorkspace, strings.ToUpper(gateWorkspace), "mesh.example.test"} {
				if c.In(err.Error()) || strings.Contains(err.Error(), secret) {
					t.Fatalf("error carries a value: %v", err)
				}
			}
		})
	}
}

func clearGate(t *testing.T) {
	t.Helper()
	for _, k := range []string{"KEEP_MESH_PROJECT_ID", "KEEP_MESH_URL", "KEEP_MESH_CANCEL_STATUS_ID", "KEEP_MESH_TOKEN_FILE", "KEEP_MESH_WORKSPACE_ID"} {
		t.Setenv(k, "")
	}
}

// The token file is read by the plugin on each call, never by the config: its
// content must not be held in Config at all.
func TestMeshGateConfigNeverHoldsTheToken(t *testing.T) {
	c := canary.New()
	p := tokenFile(t, 0o600, c.Value(0))
	gateEnv(t, p)
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.In(strings.Join([]string{cfg.MeshGate.ProjectID, cfg.MeshGate.URL, cfg.MeshGate.CancelStatusID, cfg.MeshGate.TokenFile}, "|")) {
		t.Fatal("config holds the token text")
	}
}

// KEEP_MESH_WORKSPACE_ID instead of a token file: the gate is on, the token
// comes from the installation of that workspace, and no file is named.
func TestMeshGateFromTheInstallationOfAWorkspace(t *testing.T) {
	gateEnv(t, "")
	t.Setenv("KEEP_MESH_WORKSPACE_ID", gateWorkspace)
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.MeshGate
	if !g.Enabled || g.WorkspaceID != gateWorkspace || g.TokenFile != "" {
		t.Fatalf("gate config = %+v", g)
	}
	// Neither of the two: the error names both variables.
	t.Setenv("KEEP_MESH_WORKSPACE_ID", "")
	_, err = FromEnv()
	if err == nil || !strings.Contains(err.Error(), "KEEP_MESH_TOKEN_FILE") || !strings.Contains(err.Error(), "KEEP_MESH_WORKSPACE_ID") {
		t.Fatalf("neither source: %v", err)
	}
}
