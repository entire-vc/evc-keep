package execpolicy_test

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
)

// A resolver reads "host." as the absolute name of "host". The detector must
// see the same host, or the approver is shown one thing and another resolves.
var rootDotForms = []string{
	"attacker.example.:443",
	"api.example.com.:443",
	"root@attacker.example.",
	"attacker.example。:443",
	"api.example.com。:443",
	"root@attacker.example。",
	"root@attacker.example\uff61:443",
	"root@attacker.example.:443",
	"--target=attacker.example.:443",
}

func TestRootDotHostRefusedOffline(t *testing.T) {
	for _, lit := range rootDotForms {
		if _, err := execpolicy.Validate(tpl("/opt/keep/bin/report", "--target", lit)); err == nil {
			t.Errorf("network:none: literal %q accepted", lit)
		}
	}
}

func TestRootDotHostRefusedByAllowlist(t *testing.T) {
	ok := execpolicy.Destination{Host: "ok.example.net", Port: 443}
	for _, lit := range rootDotForms {
		_, err := execpolicy.Validate(withNet(tpl("/usr/bin/curl", "--target", lit), ok))
		if !errors.Is(err, execpolicy.ErrUndeclaredDest) {
			t.Errorf("allowlist: literal %q: err = %v, want ErrUndeclaredDest", lit, err)
		}
	}
}

// A root dot on a declared host matches the declared form.
func TestRootDotOnDeclaredHostMatches(t *testing.T) {
	for _, lit := range []string{"api.github.com.:443", "https://api.github.com./x", "root@api.github.com."} {
		if _, err := execpolicy.Validate(withNet(tpl("/usr/bin/curl", lit), github)); err != nil {
			t.Errorf("declared host with root dot %q refused: %v", lit, err)
		}
	}
}

func TestRootDotControlsStayLegal(t *testing.T) {
	for _, lit := range []string{"backup.tar.gz", "e.g.", "v1.2.3", "report-2026.pdf", "end.", "."} {
		if _, err := execpolicy.Validate(tpl("/opt/keep/bin/report", lit)); err != nil {
			t.Errorf("network:none control %q refused: %v", lit, err)
		}
	}
}

// A bare name with no port, user or scheme is not address-shaped in either
// mode (existing policy, not changed here); the root dot must not change that
// verdict in either direction.
func TestRootDotBareNameVerdictUnchanged(t *testing.T) {
	ok := execpolicy.Destination{Host: "ok.example.net", Port: 443}
	for _, pair := range [][2]string{{"attacker.example", "attacker.example."}, {"backup.tar.gz", "backup.tar.gz."}} {
		for _, mk := range []func(string) execpolicy.Template{
			func(a string) execpolicy.Template { return tpl("/usr/bin/curl", a) },
			func(a string) execpolicy.Template { return withNet(tpl("/usr/bin/curl", a), ok) },
		} {
			_, e1 := execpolicy.Validate(mk(pair[0]))
			_, e2 := execpolicy.Validate(mk(pair[1]))
			if (e1 == nil) != (e2 == nil) {
				t.Errorf("%q: err %v, but %q: err %v", pair[0], e1, pair[1], e2)
			}
		}
	}
}
