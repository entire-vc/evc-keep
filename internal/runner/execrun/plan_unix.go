//go:build unix

package execrun

import (
	"os"
	"syscall"
)

func ownerUID(fi os.FileInfo) (int64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int64(st.Uid), true
}

// linkCount is the number of names the file has; 0 when unknown.
func linkCount(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(st.Nlink) //nolint:unconvert // Nlink is uint16 on darwin, uint64 on linux
}
