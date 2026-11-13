//go:build unix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// openPolicyFile opens path read-only and non-blocking, never as a controlling terminal. O_NONBLOCK keeps
// open(2) on a FIFO with no writer from waiting forever; it does not change
// reads of a regular file. Symlinks are followed, as os.ReadFile did.
func openPolicyFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "policy"), nil
}
