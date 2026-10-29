//go:build unix

package discover

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const noFollow = unix.O_NOFOLLOW

func openRoot(path string, owners []uint32) (*os.File, error) {
	f, err := os.Open("/")
	if err != nil {
		return nil, ErrRead
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		parentInfo, parentErr := f.Stat()
		if parentErr != nil || parentInfo.Mode().Perm()&0o022 != 0 || !ownerAllowed(parentInfo, owners) {
			_ = f.Close()
			return nil, ErrRead
		}
		fd, err := unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|noFollow, 0)
		_ = f.Close()
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil, errAbsent
			}
			return nil, ErrRead
		}
		f = os.NewFile(uintptr(fd), "carrier-root")
	}
	info, err := f.Stat()
	if err != nil || info.Mode().Perm()&0o022 != 0 || !ownerAllowed(info, owners) {
		_ = f.Close()
		return nil, ErrRead
	}
	return f, nil
}

func openRelative(root *os.File, path string, directory bool, owners []uint32) (*os.File, error) {
	if !safeRelative(path) {
		return nil, ErrRead
	}
	parts := strings.Split(path, "/")
	parent := root
	var owned *os.File
	defer func() {
		if owned != nil {
			_ = owned.Close()
		}
	}()
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | noFollow
		if i < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(parent.Fd()), part, flags, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil, errAbsent
			}
			return nil, ErrRead
		}
		f := os.NewFile(uintptr(fd), "carrier")
		info, err := f.Stat()
		if err != nil || info.Mode().Perm()&0o022 != 0 || !ownerAllowed(info, owners) || (i < len(parts)-1 || directory) && !info.IsDir() {
			_ = f.Close()
			return nil, ErrRead
		}
		if i == len(parts)-1 {
			return f, nil
		}
		if owned != nil {
			_ = owned.Close()
		}
		owned = f
		parent = f
	}
	return nil, ErrRead
}

func ownerAllowed(info os.FileInfo, owners []uint32) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	for _, uid := range owners {
		if st.Uid == uid {
			return true
		}
	}
	return false
}

func readBounded(f *os.File, limit int64) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, ErrRead
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	// Reject hardlinks, devices, FIFOs and sockets before reading any bytes.
	if !info.Mode().IsRegular() || !ok || st.Nlink != 1 {
		return nil, ErrRead
	}
	if info.Size() > limit {
		return nil, ErrSize
	}
	return readSized(f, info.Size(), limit)
}

// readSized separates the pinned file metadata from the bounded reader so
// growth and short reads can be tested deterministically.
func readSized(reader io.Reader, size, limit int64) ([]byte, error) {
	// Allocate once: io.ReadAll's growth can leave unwiped old byte arrays.
	if limit <= 0 || limit > 16<<20 {
		return nil, ErrPolicy
	}
	buffer := make([]byte, limit+1)
	n, err := io.ReadFull(reader, buffer)
	if int64(n) > limit {
		wipe(buffer)
		return nil, ErrSize
	}
	if err != io.EOF && err != io.ErrUnexpectedEOF || int64(n) != size {
		wipe(buffer)
		return nil, ErrRead
	}
	b := buffer[:n]
	return b, nil
}

// expand enumerates one bounded directory at a time. Even wildcard parents
// are opened via directory descriptors, without following symlinks.
func expand(ctx context.Context, root *os.File, pattern string, limit int, owners []uint32) ([]string, error) {
	paths := []string{""}
	examined := 0
	for _, part := range strings.Split(pattern, "/") {
		next := []string{}
		for _, base := range paths {
			if ctx.Err() != nil {
				return nil, ErrCanceled
			}
			if !strings.ContainsAny(part, "*?[") {
				next = append(next, filepath.Join(base, part))
				continue
			}
			var dir *os.File
			var err error
			if base == "" {
				fd, e := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|noFollow, 0)
				err = e
				if e == nil {
					dir = os.NewFile(uintptr(fd), "carrier-directory")
				}
			} else {
				dir, err = openRelative(root, base, true, owners)
			}
			if err != nil {
				if errors.Is(err, errAbsent) {
					continue
				}
				return nil, ErrRead
			}
			for {
				entries, e := dir.ReadDir(64)
				examined += len(entries)
				if examined > limit*64 {
					_ = dir.Close()
					return nil, ErrPolicy
				}
				for _, entry := range entries {
					matched, _ := filepath.Match(part, entry.Name())
					if matched {
						next = append(next, filepath.Join(base, entry.Name()))
					}
				}
				if len(next) > limit {
					_ = dir.Close()
					return nil, ErrPolicy
				}
				if e == io.EOF {
					break
				}
				if e != nil {
					_ = dir.Close()
					return nil, ErrRead
				}
				if ctx.Err() != nil {
					_ = dir.Close()
					return nil, ErrCanceled
				}
			}
			_ = dir.Close()
		}
		paths = next
		if len(paths) > limit {
			return nil, ErrPolicy
		}
	}
	sort.Strings(paths)
	return paths, nil
}
