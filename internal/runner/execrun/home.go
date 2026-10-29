package execrun

import (
	"errors"
	"io"
	"os"
)

// newRunDir makes the directory one child uses as HOME, TMPDIR and cwd: new
// for this run, owned by the child's account, closed to everyone else. What
// one child wrote there cannot be read by the next, which runs with another
// template and secret, because the next gets another directory.
func newRunDir(root string, uid, gid uint32, chown func(string, int, int) error) (string, error) {
	if chown == nil {
		chown = os.Chown
	}
	dir, err := os.MkdirTemp(root, "run-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its search bit
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := chown(dir, int(uid), int(gid)); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

var errHomeRootNotEmpty = errors.New("the home root is not empty: a leftover of an earlier run")

// homeRootEmpty reports whether nothing is left in root. A run directory
// whose removal failed stays there owned by the child's account, and the next
// child, running with another secret, could read it.
func homeRootEmpty(root string) bool {
	f, err := os.Open(root) //nolint:gosec // G304: root is the operator-set -exec-home, checked at start
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(1)
	return len(names) == 0 && errors.Is(err, io.EOF)
}
