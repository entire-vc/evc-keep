//go:build unix

package loop

import (
	"os"
	"syscall"
)

const noFollow = syscall.O_NOFOLLOW

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
