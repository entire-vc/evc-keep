package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

func selfRotateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KEEP_MESH_EXTENSION", "1")
	t.Setenv("KEEP_MESH_SELF_ROTATE", "1")
	t.Setenv("KEEP_MESH_SELF_ROTATE_URL", "https://mesh.example.test")
	t.Setenv("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID", uuid.NewString())
	t.Setenv("KEEP_MESH_SELF_ROTATE_ORG_ID", uuid.NewString())
	t.Setenv("KEEP_MESH_SELF_ROTATE_INTERVAL", "")
	t.Setenv("KEEP_MESH_SELF_ROTATE_HOOK", "")
	t.Setenv("KEEP_MESH_SELF_ROTATE_RESTART_LANE", "")
	t.Setenv("KEEP_MESH_SVC_BOOTSTRAP_FILE", "")
}

func TestSelfRotateOffByDefault(t *testing.T) {
	selfRotateEnv(t)
	t.Setenv("KEEP_MESH_SELF_ROTATE", "")
	for _, k := range []string{"KEEP_MESH_SELF_ROTATE_URL", "KEEP_MESH_SELF_ROTATE_ACCOUNT_ID", "KEEP_MESH_SELF_ROTATE_ORG_ID"} {
		t.Setenv(k, "")
	}
	g, err := meshSelfRotateFromEnv(true)
	if err != nil || g.Enabled {
		t.Fatalf("got %+v, %v; want off", g, err)
	}
}

func TestSelfRotateOn(t *testing.T) {
	selfRotateEnv(t)
	hook := filepath.Join(t.TempDir(), "hook.sh")
	t.Setenv("KEEP_MESH_SELF_ROTATE_HOOK", hook)
	t.Setenv("KEEP_MESH_SELF_ROTATE_INTERVAL", "90m")
	g, err := meshSelfRotateFromEnv(true)
	if err != nil || !g.Enabled || g.HookPath != hook || g.Interval != 90*time.Minute {
		t.Fatalf("got %+v, %v", g, err)
	}
	selfRotateEnv(t)
	if g, _ := meshSelfRotateFromEnv(true); g.Interval != DefaultMeshSelfRotateInterval {
		t.Fatalf("default interval %v", g.Interval)
	}
}

// Each broken setting stops the start with a message that names the variable
// and carries none of the value.
func TestSelfRotateRefusals(t *testing.T) {
	c := canary.New()
	cases := map[string]func(){
		"settings without the switch": func() { t.Setenv("KEEP_MESH_SELF_ROTATE", "") },
		"switch is not 1":             func() { t.Setenv("KEEP_MESH_SELF_ROTATE", "yes") },
		"url missing":                 func() { t.Setenv("KEEP_MESH_SELF_ROTATE_URL", "") },
		"url is a path":               func() { t.Setenv("KEEP_MESH_SELF_ROTATE_URL", "/m/"+c.Value(0)) },
		"account missing":             func() { t.Setenv("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID", "") },
		"account not uuid":            func() { t.Setenv("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID", "a-"+c.Value(0)) },
		"org not uuid":                func() { t.Setenv("KEEP_MESH_SELF_ROTATE_ORG_ID", "o-"+c.Value(0)) },
		"hook relative":               func() { t.Setenv("KEEP_MESH_SELF_ROTATE_HOOK", "hook-"+c.Value(0)) },
		"bootstrap relative":          func() { t.Setenv("KEEP_MESH_SVC_BOOTSTRAP_FILE", "tok-"+c.Value(0)) },
		"interval not a duration":     func() { t.Setenv("KEEP_MESH_SELF_ROTATE_INTERVAL", "soon-"+c.Value(0)) },
		"interval below a second":     func() { t.Setenv("KEEP_MESH_SELF_ROTATE_INTERVAL", "10ms") },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			selfRotateEnv(t)
			mut()
			_, err := meshSelfRotateFromEnv(true)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "KEEP_MESH_") || c.In(err.Error()) {
				t.Fatalf("message %q must name the variable and not the value", err)
			}
		})
	}
	selfRotateEnv(t)
	if _, err := meshSelfRotateFromEnv(false); err == nil {
		t.Fatal("accepted without KEEP_MESH_EXTENSION=1")
	}
}

func TestSelfRotateRestartLane(t *testing.T) {
	selfRotateEnv(t)
	t.Setenv("KEEP_MESH_SELF_ROTATE_RESTART_LANE", "Hugh")
	g, err := meshSelfRotateFromEnv(true)
	if err != nil || g.RestartLane != "Hugh" || g.HookPath != "" {
		t.Fatalf("got %+v, %v", g, err)
	}
	// The queue and the program on the server's host are alternatives.
	t.Setenv("KEEP_MESH_SELF_ROTATE_HOOK", filepath.Join(t.TempDir(), "hook.sh"))
	if _, err := meshSelfRotateFromEnv(true); err == nil {
		t.Fatal("a lane and a hook were both accepted")
	}
	// A lane alone does not switch the feature on.
	selfRotateEnv(t)
	t.Setenv("KEEP_MESH_SELF_ROTATE", "")
	for _, k := range []string{"KEEP_MESH_SELF_ROTATE_URL", "KEEP_MESH_SELF_ROTATE_ACCOUNT_ID", "KEEP_MESH_SELF_ROTATE_ORG_ID"} {
		t.Setenv(k, "")
	}
	t.Setenv("KEEP_MESH_SELF_ROTATE_RESTART_LANE", "Hugh")
	if _, err := meshSelfRotateFromEnv(true); err == nil {
		t.Fatal("a lane without KEEP_MESH_SELF_ROTATE=1 was ignored")
	}
}

// sealOnlyEnv is the seal-only shape: a bootstrap file and the organisation
// whose store seals it, with the rotation switch off.
func sealOnlyEnv(t *testing.T) string {
	t.Helper()
	selfRotateEnv(t)
	t.Setenv("KEEP_MESH_SELF_ROTATE", "")
	t.Setenv("KEEP_MESH_SELF_ROTATE_URL", "")
	t.Setenv("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID", "")
	p := filepath.Join(t.TempDir(), "svc.token")
	t.Setenv("KEEP_MESH_SVC_BOOTSTRAP_FILE", p)
	return p
}

// A bootstrap file and an organisation without KEEP_MESH_SELF_ROTATE seal the
// token and rotate nothing: SealOnly is set and Enabled is not.
func TestSealOnly(t *testing.T) {
	p := sealOnlyEnv(t)
	g, err := meshSelfRotateFromEnv(true)
	if err != nil || g.Enabled || !g.SealOnly || g.BootstrapFile != p || g.OrgID == "" {
		t.Fatalf("got %+v, %v; want seal-only", g, err)
	}
	// URL and account may stay in the environment for a later switch to rotation.
	t.Setenv("KEEP_MESH_SELF_ROTATE_URL", "https://mesh.example.test")
	t.Setenv("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID", uuid.NewString())
	if g, err := meshSelfRotateFromEnv(true); err != nil || g.Enabled || !g.SealOnly {
		t.Fatalf("got %+v, %v; want seal-only with rotation settings present", g, err)
	}
	// The switch on is rotation, not seal-only.
	selfRotateEnv(t)
	if g, err := meshSelfRotateFromEnv(true); err != nil || !g.Enabled || g.SealOnly {
		t.Fatalf("got %+v, %v; want rotation", g, err)
	}
}

// Seal-only keeps the checks of the rotation path and refuses what only a
// rotation would use: a hook or an interval without the switch.
func TestSealOnlyRefusals(t *testing.T) {
	c := canary.New()
	cases := map[string]func(){
		"org missing":        func() { t.Setenv("KEEP_MESH_SELF_ROTATE_ORG_ID", "") },
		"org not uuid":       func() { t.Setenv("KEEP_MESH_SELF_ROTATE_ORG_ID", "o-"+c.Value(0)) },
		"bootstrap relative": func() { t.Setenv("KEEP_MESH_SVC_BOOTSTRAP_FILE", "tok-"+c.Value(0)) },
		"account not uuid":   func() { t.Setenv("KEEP_MESH_SELF_ROTATE_ACCOUNT_ID", "a-"+c.Value(0)) },
		"url is a path":      func() { t.Setenv("KEEP_MESH_SELF_ROTATE_URL", "/m/"+c.Value(0)) },
		"hook without switch": func() {
			t.Setenv("KEEP_MESH_SELF_ROTATE_HOOK", filepath.Join(t.TempDir(), "hook-"+c.Value(0)))
		},
		"interval without switch": func() { t.Setenv("KEEP_MESH_SELF_ROTATE_INTERVAL", "1h") },
		"lane without switch":     func() { t.Setenv("KEEP_MESH_SELF_ROTATE_RESTART_LANE", "Hugh") },
		"switch is not 1":         func() { t.Setenv("KEEP_MESH_SELF_ROTATE", "0") },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			sealOnlyEnv(t)
			mut()
			_, err := meshSelfRotateFromEnv(true)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "KEEP_MESH_") || c.In(err.Error()) {
				t.Fatalf("message %q must name the variable and not the value", err)
			}
		})
	}
	sealOnlyEnv(t)
	if _, err := meshSelfRotateFromEnv(false); err == nil {
		t.Fatal("seal-only accepted without KEEP_MESH_EXTENSION=1")
	}
}
