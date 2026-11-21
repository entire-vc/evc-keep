package app

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// The restart allowlist comes only from KEEP_RESTART_LANES: listed lanes are
// accepted and nothing else; without the variable the queue accepts none and
// the start logs exactly one line that names the variable, not a lane.
func TestRestartQueueFromConfig(t *testing.T) {
	var logs bytes.Buffer
	q := restartQueue(nil, []string{"worker", "other"}, obs.New(&logs))
	for lane, want := range map[string]bool{"worker": true, "other": true, "third": false, "Worker": false, "": false} {
		if q.Allows(lane) != want {
			t.Errorf("lane %q: allowed=%v, want %v", lane, !want, want)
		}
	}
	if logs.Len() != 0 {
		t.Fatalf("a configured allowlist logged: %s", logs.String())
	}

	for _, lanes := range [][]string{nil, {}} {
		logs.Reset()
		q = restartQueue(nil, lanes, obs.New(&logs))
		for _, lane := range []string{"worker", "other", "Test", "test"} {
			if q.Allows(lane) {
				t.Errorf("lanes %q: %q allowed with no allowlist", lanes, lane)
			}
		}
		out := logs.String()
		if strings.Count(out, "\n") != 1 || !strings.Contains(out, "KEEP_RESTART_LANES") {
			t.Fatalf("lanes %q: want one line naming KEEP_RESTART_LANES, got %q", lanes, out)
		}
		for _, lane := range []string{"worker", "other", "Test", "test"} {
			if strings.Contains(out, lane) {
				t.Fatalf("the startup line names a lane: %q", out)
			}
		}
	}
}

// The served process reads the allowlist from its environment: unset, it
// starts and logs the no-lanes line; set, it starts without that line; a
// malformed name stops it before it listens, naming the variable only.
func TestServeRestartLanes(t *testing.T) {
	bin := buildKeepServer(t)
	dsn := pgscratch.New(t, requiredLogSettingsLiteral)
	migrate(t, bin, dsn)
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")
	const line = "restart queue has no lanes"

	t.Run("unset refuses every lane", func(t *testing.T) {
		out, running, code := serveWithEnv(t, bin, roleDSN, 3*time.Second)
		if !running || strings.Count(out, line) != 1 {
			t.Fatalf("running=%v code=%d, want running with one no-lanes line: %q", running, code, out)
		}
	})
	t.Run("set is used", func(t *testing.T) {
		out, running, code := serveWithEnv(t, bin, roleDSN, 3*time.Second, "KEEP_RESTART_LANES=worker,other")
		if !running || strings.Contains(out, line) {
			t.Fatalf("running=%v code=%d, want running without the no-lanes line: %q", running, code, out)
		}
	})
	t.Run("malformed stops the start", func(t *testing.T) {
		out, running, code := serveWithEnv(t, bin, roleDSN, 15*time.Second, "KEEP_RESTART_LANES=worker;canary-lane")
		if running || code != 1 || !strings.Contains(out, "KEEP_RESTART_LANES") || strings.Contains(out, "canary-lane") || strings.Contains(out, "listening") {
			t.Fatalf("running=%v code=%d, want exit 1 naming the variable only, before listening: %q", running, code, out)
		}
	})
}
