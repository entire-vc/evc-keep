//go:build unix

package runnerproto

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LoadHostPolicy reads the policy file at path. The file must be a regular
// file, not a symlink, owned by ownerUID (the runner's own user) and
// accessible by nobody else: a policy an agent can edit is no policy.
func LoadHostPolicy(path string, ownerUID int) (HostPolicy, error) {
	// O_NONBLOCK: open(2) of a FIFO without a writer would block forever,
	// before the regular-file check below could refuse it. It has no effect
	// on a regular file.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: path is the runner's configured policy file
	if err != nil {
		return HostPolicy{}, fmt.Errorf("runnerproto: host policy: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return HostPolicy{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return HostPolicy{}, errors.New("runnerproto: host policy is not a regular file")
	case fi.Mode().Perm()&0o077 != 0:
		return HostPolicy{}, errors.New("runnerproto: host policy must be mode 0600")
	case !ok || int64(st.Uid) != int64(ownerUID):
		return HostPolicy{}, errors.New("runnerproto: host policy is not owned by the runner user")
	}
	// Read one byte past the cap: a file longer than maxHostPolicyBytes is
	// refused, never truncated to a valid-looking prefix. The size from stat
	// is not trusted (the file may grow after it); the read itself decides.
	b, err := io.ReadAll(io.LimitReader(f, maxHostPolicyBytes+1))
	if err != nil {
		return HostPolicy{}, err
	}
	if len(b) > maxHostPolicyBytes {
		return HostPolicy{}, errors.New("runnerproto: host policy exceeds the size limit")
	}
	return ParseHostPolicy(b)
}

// maxHostPolicyBytes is the largest policy file LoadHostPolicy accepts.
const maxHostPolicyBytes = 1 << 20

// CheckPrefixesOnHost walks every rule's path prefixes on this host from "/"
// with lstat and refuses one that passes through a symlink or a non-directory.
// The target writer opens each component with O_NOFOLLOW, so such a prefix
// would admit a job that is then denied on every write — on macOS /var, /tmp
// and /etc are symlinks into /private. A missing tail is fine: it does not
// exist yet, and the writer still refuses whatever appears there later.
// ParseHostPolicy does not call this: a policy parses without its host.
//
// A refusal is a *PrefixError: Error() is the detailed text for the library's
// own callers, while Class, Rule and Prefix are the closed, content-free fields
// a CLI may print (the policy file is arbitrary text, so its prefixes and path
// components are not safe to echo).
func CheckPrefixesOnHost(p HostPolicy) error {
	for i, r := range p.Targets {
		for j, pre := range r.PathPrefixes {
			if class, err := checkPrefixOnHost(pre); err != nil {
				return &PrefixError{Class: class, Rule: i, Prefix: j,
					msg: fmt.Sprintf("runnerproto: host policy: rule %d (%s): prefix %q %v", i, r.Kind, pre, err), err: err}
			}
		}
	}
	return nil
}

// Prefix refusal classes of PrefixError.Class.
const (
	PrefixSymlink      = "symlink"
	PrefixNotDirectory = "not_directory"
	PrefixLstatError   = "lstat_error"
)

// PrefixError is a refused path prefix. Its Error() and Unwrap() carry policy
// content (prefix, components, resolved path): never print them from a CLI or
// log them, use Class, Rule and Prefix. Rule and Prefix are zero-based indexes
// into the policy's targets and that rule's path_prefixes.
type PrefixError struct {
	Class  string
	Rule   int
	Prefix int
	msg    string
	err    error
}

func (e *PrefixError) Error() string { return e.msg }
func (e *PrefixError) Unwrap() error { return e.err }

func checkPrefixOnHost(prefix string) (string, error) {
	cur := "/"
	for _, seg := range strings.Split(strings.TrimPrefix(prefix, "/"), "/") {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", nil
		case err != nil:
			return PrefixLstatError, fmt.Errorf("component %q cannot be checked: %w", cur, err)
		case fi.Mode()&fs.ModeSymlink != 0:
			hint := ""
			if real, err := filepath.EvalSymlinks(cur); err == nil {
				hint = fmt.Sprintf(" (use the real path %q)", filepath.Join(real, strings.TrimPrefix(prefix, cur)))
			}
			return PrefixSymlink, fmt.Errorf("component %q is a symlink%s", cur, hint)
		case !fi.IsDir():
			return PrefixNotDirectory, fmt.Errorf("component %q is not a directory", cur)
		}
	}
	return "", nil
}
