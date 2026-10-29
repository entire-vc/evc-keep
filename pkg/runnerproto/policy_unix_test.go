//go:build unix

package runnerproto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A prefix through a symlink passes Check but every write under it is refused
// by the target writer's O_NOFOLLOW walk; the host check names the component.
// The symlink is made here, not taken from /var: on Linux /var is a plain
// directory and the test would have nothing to catch.
func TestCheckPrefixesOnHost(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(realDir, "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pol := func(prefixes ...string) HostPolicy {
		return HostPolicy{Version: 1, Targets: []TargetRule{
			{Kind: TargetEnvFile, PathPrefixes: []string{realDir}},
			{Kind: TargetFile, PathPrefixes: prefixes},
		}}
	}

	for name, pre := range map[string]string{
		"real path":    filepath.Join(realDir, "lib"),
		"missing tail": filepath.Join(realDir, "lib", "not", "yet"),
		"missing dir":  filepath.Join(base, "absent"),
	} {
		if err := CheckPrefixesOnHost(pol(pre)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, tc := range map[string]struct{ prefix, component string }{
		"symlink component": {filepath.Join(link, "lib"), link},
		"symlink leaf":      {link, link},
		"file component":    {filepath.Join(file, "x"), file},
	} {
		err := CheckPrefixesOnHost(pol(tc.prefix))
		if err == nil {
			t.Errorf("%s: prefix %q accepted", name, tc.prefix)
			continue
		}
		msg := err.Error()
		for _, want := range []string{`rule 1 (file)`, `component "` + tc.component + `"`} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: error %q lacks %q", name, msg, want)
			}
		}
	}
	err = CheckPrefixesOnHost(pol(filepath.Join(link, "lib")))
	if err == nil || !strings.Contains(err.Error(), "is a symlink") || !strings.Contains(err.Error(), filepath.Join(realDir, "lib")) {
		t.Errorf("symlink error does not name the real path: %v", err)
	}
	if err := CheckPrefixesOnHost(HostPolicy{Version: 1}); err != nil {
		t.Errorf("empty policy: %v", err)
	}
}
