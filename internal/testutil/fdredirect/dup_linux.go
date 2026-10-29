package fdredirect

import "golang.org/x/sys/unix"

// Dup2 makes newfd refer to the same open file as oldfd. dup3 exists on
// every linux architecture; dup2 is missing on arm64. dup3 rejects
// oldfd == newfd with EINVAL where dup2 is a no-op on a valid descriptor
// (and EBADF on an invalid one), so that case only probes the descriptor.
func Dup2(oldfd, newfd int) error {
	if oldfd == newfd {
		_, err := unix.FcntlInt(uintptr(oldfd), unix.F_GETFD, 0)
		return err
	}
	return unix.Dup3(oldfd, newfd, 0)
}
