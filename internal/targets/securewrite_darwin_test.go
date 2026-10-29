//go:build darwin

package targets

import (
	"os"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// TestVarIsASymlinkOnDarwin documents and proves the macOS gotcha behind
// realDir in testutil_test.go: /var (and /etc, /tmp) is a symlink to
// /private/var, so a HostPolicy prefix or a target path written as
// "/var/..." is refused by Write's own symlink defense on this platform —
// the same defense every other symlink test in this file exercises
// deliberately. Administrators must write policy prefixes under
// /private/var (etc.), not /var; the same holds for /etc and /tmp.
func TestVarIsASymlinkOnDarwin(t *testing.T) {
	fi, err := os.Lstat("/var")
	if err != nil {
		t.Fatalf("lstat /var: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("/var is not a symlink on this host — the gotcha this test documents no longer holds; realDir's workaround may be unnecessary")
	}
	uids, gids := noAgents()
	_, err = Write(target(runnerproto.TargetFile, "/var/keep-w24-test-should-not-exist", ""), newValue("x"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "write under /var (a symlink)")
}
