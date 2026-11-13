package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func lookupOf(set map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := set[k]; return v, ok }
}

// A build without the rotation plugin must stop on any of its settings, not
// hand a secret meant for Mesh to the generator.
func TestCheckRotatorSettings_CoreRefusesAnyOfThree(t *testing.T) {
	const canary = "/canary-value-must-not-be-printed"
	for _, name := range rotatorSettings {
		err := checkRotatorSettings(Options{}, lookupOf(map[string]string{name: canary}))
		if err == nil {
			t.Fatalf("%s alone must refuse the start", name)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("%s: the value leaked into the error", name)
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: the error must name the variable", name)
		}
	}
	full := map[string]string{}
	for _, name := range rotatorSettings {
		full[name] = canary
	}
	if checkRotatorSettings(Options{}, lookupOf(full)) == nil {
		t.Fatal("the full set must refuse the start")
	}
	// An empty value is still a configuration asked for.
	if checkRotatorSettings(Options{}, lookupOf(map[string]string{rotatorSettings[0]: ""})) == nil {
		t.Fatal("an empty value must refuse the start")
	}
}

func TestCheckRotatorSettings_NoneOrPluginBuildPasses(t *testing.T) {
	if err := checkRotatorSettings(Options{}, lookupOf(nil)); err != nil {
		t.Fatalf("no settings: %v", err)
	}
	full := map[string]string{}
	for _, name := range rotatorSettings {
		full[name] = "x"
	}
	plugin := Options{Rotators: func(*slog.Logger) (RotatorSource, error) { return nil, nil }}
	if err := checkRotatorSettings(plugin, lookupOf(full)); err != nil {
		t.Fatalf("a build with the plugin must pass: %v", err)
	}
}

// The check runs in the real start path before the database is touched: with
// an unreachable database the refusal still names the setting.
func TestRunServe_RefusesRotateSettingsBeforeDatabase(t *testing.T) {
	t.Setenv("KEEP_DATABASE_URL", "postgres://127.0.0.1:1/keep?sslmode=disable&connect_timeout=1")
	t.Setenv("KEEP_DEV_EPHEMERAL_TLS", "1")
	t.Setenv("KEEP_MESH_ROTATE_URL", "https://mesh.example.test")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	code := runServe(context.Background(), slog.New(slog.DiscardHandler), Options{})
	os.Stderr = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	// The captured text is not printed on failure: without the check the start
	// reaches the database and its error is not this test's evidence.
	if code != 1 || !strings.Contains(string(out), "KEEP_MESH_ROTATE_URL") {
		t.Fatalf("exit %d, no refusal naming the setting (%d bytes of output)", code, len(out))
	}
	if strings.Contains(string(out), "mesh.example.test") {
		t.Fatal("the value leaked into the message")
	}
}
