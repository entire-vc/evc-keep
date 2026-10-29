//go:build unix

package builtin

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readLocalRoot(path string) ([]byte, error) {
	return readLocalRootWith(path, io.ReadAll)
}

func readLocalRootWith(path string, readAll func(io.Reader) ([]byte, error)) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLocalKey
	}
	file := os.NewFile(uintptr(fd), "root key")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errLocalKey
	}
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, errLocalKey
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || int64(st.Uid) != int64(os.Geteuid()) {
		return nil, errLocalKey
	}
	// Bound allocations while permitting the base64 spelling and surrounding
	// whitespace. Read one extra byte so oversized files cannot be truncated
	// into an accepted root.
	const maxRootFile = 4096
	raw, err := readAll(io.LimitReader(file, maxRootFile+1))
	if err != nil || len(raw) > maxRootFile {
		clear(raw[:])
		return nil, errLocalKey // root read
	}
	return raw, nil
}
