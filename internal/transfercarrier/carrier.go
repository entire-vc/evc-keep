//go:build unix

// Package transfercarrier is the one way an offline transfer puts a private
// artifact (recipient private key, sealed bundle, approval) on disk and reads
// one back. A carrier is created new, mode 0600, never replaces anything and
// never follows a symlink; a read refuses anything that is not a plain file
// owned by the caller with no group or world access. Errors are closed
// reasons: they carry neither the path nor any content.
package transfercarrier

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Error is the only error this package returns.
type Error struct{ Reason string }

func (e Error) Error() string { return "transfer carrier refused: " + e.Reason }

func refuse(reason string) error { return Error{Reason: reason} }

// Create writes data to a new file at dest. dest must be absolute and not
// exist (not even as a dangling symlink); its directory must be a real
// directory owned by the caller that is not writable by group or others.
// The data is written to an unlinked-on-failure temporary file in the same
// directory and linked into place, so dest never holds a partial carrier and
// an existing name is never replaced.
func Create(dest string, data []byte) error {
	if !filepath.IsAbs(dest) || filepath.Clean(dest) != dest {
		return refuse("path")
	}
	dir := filepath.Dir(dest)
	if err := checkDir(dir); err != nil {
		return err
	}
	if _, err := os.Lstat(dest); err == nil {
		return refuse("exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return refuse("path")
	}
	tmp, err := os.CreateTemp(dir, ".keep-transfer-*")
	if err != nil {
		return refuse("write")
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return refuse("write")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return refuse("write")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return refuse("write")
	}
	if err := tmp.Close(); err != nil {
		return refuse("write")
	}
	if err := os.Link(name, dest); err != nil {
		if errors.Is(err, os.ErrExist) {
			return refuse("exists")
		}
		return refuse("write")
	}
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- dir was validated above
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Read returns the content of the carrier at path. It refuses a symlink, a
// non-regular file (a FIFO or device never blocks the caller), a file owned
// by another user, a file readable or writable by group or others, and one
// larger than max bytes. The caller owns and must clear the result.
func Read(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || max <= 0 {
		return nil, refuse("path")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, refuse("open")
	}
	f := os.NewFile(uintptr(fd), "carrier")
	defer func() { _ = f.Close() }()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil {
		return nil, refuse("open")
	}
	switch {
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return nil, refuse("not_regular")
	case int(st.Uid) != os.Geteuid():
		return nil, refuse("owner")
	case st.Mode&0o077 != 0:
		return nil, refuse("mode")
	case st.Size > max:
		return nil, refuse("size")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		clear(data)
		return nil, refuse("read")
	}
	return data, nil
}

// Destroy overwrites the carrier at path with zeros, syncs it and removes it.
// It applies Read's refusals (symlink, non-regular, other owner, group or
// world access), so it never touches a file the caller does not own.
func Destroy(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return refuse("path")
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return refuse("open")
	}
	f := os.NewFile(uintptr(fd), "carrier")
	defer func() { _ = f.Close() }()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil {
		return refuse("open")
	}
	switch {
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return refuse("not_regular")
	case int(st.Uid) != os.Geteuid():
		return refuse("owner")
	case st.Mode&0o077 != 0:
		return refuse("mode")
	}
	zeros := make([]byte, 4096)
	for left := st.Size; left > 0; {
		n := int64(len(zeros))
		if left < n {
			n = left
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			return refuse("write")
		}
		left -= n
	}
	if f.Sync() != nil {
		return refuse("write")
	}
	if os.Remove(path) != nil {
		return refuse("remove")
	}
	return nil
}

func checkDir(dir string) error {
	var st syscall.Stat_t
	if syscall.Lstat(dir, &st) != nil {
		return refuse("directory")
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
		return refuse("directory")
	}
	return nil
}
