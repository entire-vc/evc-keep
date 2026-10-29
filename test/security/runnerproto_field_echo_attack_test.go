// Attack on pkg/runnerproto.Check (threat model §7.1, card
// d037165f-369f-4ccc-8298-fbaf3c82c6ee): a deploy job's Target.Field is the
// field's *name* inside the consumer's file — chosen by whoever creates the
// job, and that can be an agent. A consumer that reads that name as an
// option of its own interpreter or loader echoes the value into its own
// output instead of just holding it:
//
//	$ env -i PYTHONWARNINGS=<value> python3 -c pass
//	Invalid -W option ignored: invalid action: '<value>'
//
// If an agent can read the consumer's stderr or log (§2.3 I), the value has
// left Keep without ever touching an API endpoint. Some names (NODE_OPTIONS,
// LD_PRELOAD, BASH_ENV, …) do worse than echo: they run code.
//
// This is written against pkg/runnerproto's exported API only, and it does
// not attack the part of the contract that is easy to get right — a field
// missing from a rule's Fields list (card d037165f's own tests cover that).
// It attacks the part that is easy to get wrong: a host policy whose Fields
// list explicitly names the echo/loader field, the way a confused or
// compromised administrator's config might. The refusal has to come from
// the runner refusing to trust that entry, not from the field being absent.
package security

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	osexec "os/exec"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

var fieldEchoT0 = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func fieldEchoJobID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// fieldEchoPolicy builds a host policy the way ParseHostPolicy's own
// Validate would accept it: one rule per (kind, path), and — the point of
// this file — a Fields list that DOES include the field under attack. The
// question this file asks is not "did the administrator forget to list the
// field" (card d037165f's own tests already cover an unlisted field), it is
// "what if the administrator listed it": does the runner still refuse, on
// its own, an echo/loader name the human config explicitly allowed.
func fieldEchoPolicy(kind runnerproto.TargetKind, prefix string, fields ...string) runnerproto.HostPolicy {
	return runnerproto.HostPolicy{
		Version:           1,
		MaxDeploysPerHour: 100,
		// The opt-in is on: this file attacks the echo list, the second
		// layer, so the name-shape layer must not be what refuses.
		Targets: []runnerproto.TargetRule{{Kind: kind, PathPrefixes: []string{prefix}, Fields: fields, AllowNonCredentialName: true}},
	}
}

func fieldEchoJob(t *testing.T, kind runnerproto.TargetKind, path, field string) runnerproto.Job {
	t.Helper()
	return runnerproto.Job{
		JobID:    fieldEchoJobID(t),
		OrgID:    "acme",
		RunnerID: "runner-1",
		Secret: runnerproto.SecretRef{
			StoreID: "store-1", Provider: runnerproto.ProviderBuiltin,
			Name: "svc/token", Scope: "prod",
		},
		ExpectedVersion:     "1",
		ExpectedFingerprint: "kfp1:s1:abcdefghijklmnop",
		Action:              runnerproto.ActionDeploy,
		Target: runnerproto.Target{
			Kind: kind, Path: path, Field: field,
			Unit: "app.service", Mode: 0o640, UID: 1001, GID: 1001,
		},
		IssuedAt: fieldEchoT0,
		NotAfter: fieldEchoT0.Add(5 * time.Minute),
		Nonce:    bytes.Repeat([]byte{9}, runnerproto.NonceSize),
	}
}

// TestRunnerCheck_FieldNameEchoRefused is the attack: for every field name a
// consumer reads as its own interpreter or loader option, Check must refuse
// the job even when the rule's own Fields list names that exact field — an
// allowlist alone does not buy this property, because the name a human
// administrator typed in is exactly the thing under attack here.
func TestRunnerCheck_FieldNameEchoRefused(t *testing.T) {
	// Positive control: an ordinary field, explicitly listed the way the
	// contract requires, deploys. If this fails, every refusal below is
	// meaningless — it would prove nothing about field names specifically.
	envPolicy := fieldEchoPolicy(runnerproto.TargetEnvFile, "/etc/keep/app", "STRIPE_KEY")
	ok := fieldEchoJob(t, runnerproto.TargetEnvFile, "/etc/keep/app/app.env", "STRIPE_KEY")
	if err := runnerproto.Check(ok, envPolicy); err != nil {
		t.Fatalf("positive control: ordinary field refused: %v", err)
	}
	mcpPolicy := fieldEchoPolicy(runnerproto.TargetMCPConfig, "/etc/keep/mcp", "mcpServers.stripe.env.API_KEY")
	okMCP := fieldEchoJob(t, runnerproto.TargetMCPConfig, "/etc/keep/mcp/config.json", "mcpServers.stripe.env.API_KEY")
	if err := runnerproto.Check(okMCP, mcpPolicy); err != nil {
		t.Fatalf("positive control: ordinary mcp-config field refused: %v", err)
	}

	envFields := []string{
		"PYTHONWARNINGS", "pythonwarnings", "NODE_OPTIONS", "LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES", "JAVA_TOOL_OPTIONS", "PERL5OPT", "RUBYOPT",
		"BASH_ENV", "https_proxy", "GIT_SSH_COMMAND",
	}
	for _, field := range envFields {
		field := field
		t.Run("env-file/"+field, func(t *testing.T) {
			// The rule's own Fields list names this exact field: the
			// administrator's config, taken at face value, allows it.
			policy := fieldEchoPolicy(runnerproto.TargetEnvFile, "/etc/keep/app", field)
			j := fieldEchoJob(t, runnerproto.TargetEnvFile, "/etc/keep/app/app.env", field)
			err := runnerproto.Check(j, policy)
			if !errors.Is(err, runnerproto.ErrPolicy) {
				t.Errorf("field %q allowed by the rule's own Fields list: got %v, want ErrPolicy (this name is read as an interpreter/loader option and echoes its value)", field, err)
			}
		})
	}

	// mcp-config keeps a dotted key path; the match must be on the last
	// segment, not the whole key, even when the full dotted key is the one
	// the rule lists.
	t.Run("mcp-config/mcpServers.x.env.NODE_OPTIONS", func(t *testing.T) {
		const field = "mcpServers.x.env.NODE_OPTIONS"
		policy := fieldEchoPolicy(runnerproto.TargetMCPConfig, "/etc/keep/mcp", field)
		j := fieldEchoJob(t, runnerproto.TargetMCPConfig, "/etc/keep/mcp/config.json", field)
		err := runnerproto.Check(j, policy)
		if !errors.Is(err, runnerproto.ErrPolicy) {
			t.Errorf("dotted field ending in NODE_OPTIONS, allowed by the rule's own Fields list: got %v, want ErrPolicy", err)
		}
	})

	// A field the rule's Fields list never mentions at all must already be
	// refused for an unrelated reason — not the property under attack here
	// (card d037165f's own tests own that one), just a sanity check that the
	// harness above is wired to a real path/kind/field match and the
	// positive control isn't vacuously passing some other way.
	t.Run("sanity/unlisted-field-still-refused", func(t *testing.T) {
		j := fieldEchoJob(t, runnerproto.TargetEnvFile, "/etc/keep/app/app.env", "SOME_OTHER_KEY")
		if err := runnerproto.Check(j, envPolicy); !errors.Is(err, runnerproto.ErrPolicy) {
			t.Errorf("field outside the rule's Fields list: got %v, want ErrPolicy", err)
		}
	})
}

// TestRunnerCheck_FieldNameEchoLiveChannel demonstrates, against a real
// python3, that the channel TestRunnerCheck_FieldNameEchoRefused defends
// against is real and not a theoretical reading of python's option parser:
// a value placed in PYTHONWARNINGS reaches the consumer's stderr byte for
// byte, with every other variable cleared (env -i) so nothing else could
// have carried it. It prints only the canary's length and whether it was
// found, never the value or the environment (24.09 incident with
// systemdcred_test.go printing a whole env on failure).
func TestRunnerCheck_FieldNameEchoLiveChannel(t *testing.T) {
	python3, err := osexec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH: cannot demonstrate the live channel")
	}
	c := canary.New()
	v := c.Value(1)

	cmd := osexec.Command(python3, "-c", "pass") //nolint:gosec // G204: python3 is resolved by LookPath, args are fixed literals
	cmd.Env = []string{"PYTHONWARNINGS=" + v}    // env -i equivalent: nothing else reaches the child
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run() // python3 exits 0 even with an invalid -W action; only stderr matters here

	found := c.In(stderr.String())
	t.Logf("canary length=%d found_in_stderr=%v", len(v), found)
	if !found {
		t.Fatalf("expected python3 to echo PYTHONWARNINGS into stderr (canary length %d not found); the live-channel demonstration no longer reproduces", len(v))
	}
}
