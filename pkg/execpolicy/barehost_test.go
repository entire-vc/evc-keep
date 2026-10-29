package execpolicy_test

import (
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/execpolicy"
)

// In allowlist mode a bare dotted Latin name is an address: the approver at
// 4.5 must be shown it, so an undeclared one is refused.
func TestBareLatinHostRefusedByAllowlist(t *testing.T) {
	ok := execpolicy.Destination{Host: "ok.example.net", Port: 443}
	for _, lit := range []string{"attacker.example", "api.example.com", "Attacker.Example"} {
		_, err := execpolicy.Validate(withNet(tpl("/usr/bin/curl", lit), ok))
		if !errors.Is(err, execpolicy.ErrUndeclaredDest) {
			t.Errorf("allowlist: bare host %q: err = %v, want ErrUndeclaredDest", lit, err)
		}
	}
}

func TestBareLatinHostDeclaredAccepted(t *testing.T) {
	d := execpolicy.Destination{Host: "attacker.example", Port: 443}
	if _, err := execpolicy.Validate(withNet(tpl("/usr/bin/curl", "attacker.example"), d)); err != nil {
		t.Errorf("declared bare host refused: %v", err)
	}
}

// Positive control: file names stay files in allowlist mode.
func TestBareFileNamesStayFilesInAllowlist(t *testing.T) {
	ok := execpolicy.Destination{Host: "ok.example.net", Port: 443}
	for _, lit := range []string{"backup.tar.gz", "report.txt", "\u043e\u0442\u0447\u0451\u0442.pdf", "notes.md", "REPORT.TXT", "Backup.TAR.GZ"} {
		if _, err := execpolicy.Validate(withNet(tpl("/usr/bin/curl", lit), ok)); err != nil {
			t.Errorf("allowlist: file name %q refused: %v", lit, err)
		}
	}
}

// network:none keeps its behaviour: a plain Latin literal is not an address.
func TestBareLatinLiteralUnchangedOffline(t *testing.T) {
	for _, lit := range []string{"attacker.example", "backup.tar.gz", "report.txt"} {
		if _, err := execpolicy.Validate(tpl("/opt/keep/bin/report", lit)); err != nil {
			t.Errorf("network:none: literal %q refused: %v", lit, err)
		}
	}
}

// A networked placeholder value that is dotted and ends in a listed file
// extension is not caught by the address scan (it reads as a file name), so
// hostLike alone must refuse it, raw and folded.
func TestExpandNetworkedFileLikeValuesRefused(t *testing.T) {
	loose := map[string]execpolicy.Param{"v": {Pattern: `^[^ ]+$`}}
	net := withNet(withParams(tpl("/usr/bin/curl", "https://api.github.com/x", "{v}"), loose), github)
	for _, v := range []string{"backup.tar.gz", "\u043e\u0442\u0447\u0451\u0442.pdf", "\u043e\u0442\u0447\u0451\u0442\u3002pdf", "report\uff0etxt"} {
		if _, err := execpolicy.Expand(net, map[string]string{"v": v}); !errors.Is(err, execpolicy.ErrArgValue) {
			t.Errorf("networked value %q: got %v, want ErrArgValue", v, err)
		}
	}
}
