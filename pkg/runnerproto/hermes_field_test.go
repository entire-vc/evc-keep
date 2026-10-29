package runnerproto

import (
	"errors"
	"strings"
	"testing"
)

// hermes-config writes a NAME=value line into $HERMES_HOME/.env, so its Field
// is an environment variable name exactly as env-file's is. A dotted key path
// is what mcp-config takes and no longer what hermes-config takes.
func TestHermesConfigFieldIsEnvName(t *testing.T) {
	ok := deployJob(t)
	ok.Target.Kind = TargetHermesConfig
	ok.Target.Field = "EXAMPLE_API_KEY"
	if err := ok.Validate(); err != nil {
		t.Fatalf("positive control: env name refused: %v", err)
	}

	for name, field := range map[string]string{
		"dotted path":     "mcp_servers.x.env.K",
		"two segments":    "a.b",
		"empty":           "",
		"leading digit":   "1KEY",
		"hyphen":          "EXAMPLE-KEY",
		"line injection":  "A=B\nC",
		"too long":        strings.Repeat("A", 129),
		"trailing dot":    "KEY.",
		"space":           "EXAMPLE KEY",
		"assignment sign": "A=B",
	} {
		j := deployJob(t)
		j.Target.Kind = TargetHermesConfig
		j.Target.Field = field
		if err := j.Validate(); !errors.Is(err, ErrInvalidJob) {
			t.Errorf("%s (%q): want ErrInvalidJob, got %v", name, field, err)
		}
	}
}

// mcp-config keeps the dotted key path: the change above must not leak there.
func TestMCPConfigKeepsDottedField(t *testing.T) {
	j := deployJob(t)
	j.Target.Kind = TargetMCPConfig
	j.Target.Field = "mcpServers.x.env.K"
	if err := j.Validate(); err != nil {
		t.Fatalf("mcp-config dotted field refused: %v", err)
	}
	j.Target.Field = "PLAIN"
	if err := j.Validate(); err != nil {
		t.Fatalf("mcp-config single-segment field refused: %v", err)
	}
}
