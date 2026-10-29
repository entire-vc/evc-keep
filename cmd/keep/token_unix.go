//go:build unix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// openTokenFileNoFollow opens path for reading, refusing a symlink at that
// exact location rather than following it. A post-open Stat cannot tell a
// followed symlink's target apart from an ordinary regular file opened
// directly, so the refusal has to happen at open time: O_NOFOLLOW is the
// only way to make "the bytes resolveToken reads" and "the file its caller
// configured" the same file.
func openTokenFileNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
