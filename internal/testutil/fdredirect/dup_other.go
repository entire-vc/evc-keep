//go:build unix && !linux

package fdredirect

import "golang.org/x/sys/unix"

// Dup2 makes newfd refer to the same open file as oldfd.
func Dup2(oldfd, newfd int) error { return unix.Dup2(oldfd, newfd) }
