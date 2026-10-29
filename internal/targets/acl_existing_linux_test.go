//go:build linux

package targets

import (
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// An existing target that carries an access ACL may already grant an agent
// write access mode bits do not show; for a kind that folds the existing
// content into the new file it is refused, for one that replaces the file
// wholesale it is not read at all.
func TestExistingTargetWithACLRefusedWhenFolded(t *testing.T) {
	path := filepath.Join(safeDir(t), "svc.env")
	mustWriteFile(t, path, []byte("A=1\n"), 0o600)
	setACL(t, path, xattrACLAccess, grantUserACL(4242, 6))
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetEnvFile, path, "X"), newValue("v"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "existing env-file with an extended ACL")
	if got := mustReadFile(t, path); string(got) != "A=1\n" {
		t.Fatalf("target changed despite the refusal: %s", show(got))
	}
}

func TestExistingTargetWithACLIgnoredWhenReplacedWholesale(t *testing.T) {
	path := filepath.Join(safeDir(t), "svc")
	mustWriteFile(t, path, []byte("old"), 0o600)
	setACL(t, path, xattrACLAccess, grantUserACL(4242, 6))
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetFile, path, ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := mustReadFile(t, path); string(got) != "v" {
		t.Fatalf("target not replaced: %s", show(got))
	}
}
