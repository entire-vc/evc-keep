package security

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// The echo-name list cannot be complete: every review round found a consumer
// that prints a variable it reads. The first layer is therefore the shape of
// the name (threat model 7.1): a rule lists only credential-shaped names
// unless the administrator opts in on that rule. These are names that echo
// their value in a real consumer and are not on the shape.
func TestRunnerCheck_NonCredentialFieldNeedsOptIn(t *testing.T) {
	policy := func(open bool, field string) runnerproto.HostPolicy {
		return runnerproto.HostPolicy{
			Version: 1, MaxDeploysPerHour: 100,
			Targets: []runnerproto.TargetRule{{
				Kind: runnerproto.TargetEnvFile, PathPrefixes: []string{"/etc/keep/app"},
				Fields: []string{field}, AllowNonCredentialName: open,
			}},
		}
	}
	check := func(open bool, field string) error {
		j := fieldEchoJob(t, runnerproto.TargetEnvFile, "/etc/keep/app/app.env", field)
		return runnerproto.Check(j, policy(open, field))
	}
	// Positive controls: without them a refusal proves nothing.
	for _, f := range []string{"GITHUB_TOKEN", "NODE_AUTH_TOKEN", "STRIPE_API_KEY"} {
		if err := check(false, f); err != nil {
			t.Fatalf("positive control %s: %v", f, err)
		}
	}
	for _, f := range []string{
		"LINT", "MAKE", "MAKE_COMMAND", "OBJCPLUS_INCLUDE_PATH", "RSYNC_RSH",
		"DOCKER_DEFAULT_PLATFORM", "DOCKER_CERT_PATH", "COMPOSE_FILE", "COMPOSE_ENV_FILES",
		"PERL_SIGNALS", "RUBY_GC_HEAP_INIT_SLOTS", "AWS_PROFILE", "COLUMNS", "CUSTOM_NAME",
	} {
		if err := check(false, f); !errors.Is(err, runnerproto.ErrPolicy) {
			t.Errorf("%s without the opt-in: got %v, want ErrPolicy", f, err)
		}
	}
	// The opt-in admits a custom name, never one the echo list knows.
	if err := check(true, "CUSTOM_NAME"); err != nil {
		t.Errorf("CUSTOM_NAME with the opt-in: %v", err)
	}
	for _, f := range []string{"LINT", "MAKE", "RSYNC_RSH", "COMPOSE_FILE", "DOCKER_CERT_PATH", "VAULT_CLIENT_KEY", "TF_VAR_db_password"} {
		if err := check(true, f); !errors.Is(err, runnerproto.ErrPolicy) {
			t.Errorf("%s with the opt-in: got %v, want ErrPolicy", f, err)
		}
	}
}
