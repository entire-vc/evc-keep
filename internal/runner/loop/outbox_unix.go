//go:build unix

package loop

import (
	"os"
	"syscall"
)

// openFlags: O_NOFOLLOW refuses a symlink; O_NONBLOCK makes open(2) of a FIFO
// without a writer return at once so the regular-file check on the same
// descriptor can refuse it (it has no effect on reads of a regular file);
// O_NOCTTY keeps a tty from becoming the controlling terminal.
const noFollow = syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_NOCTTY

func ownedByUs(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the runner's own outbox directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
