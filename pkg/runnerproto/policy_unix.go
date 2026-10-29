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
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: path is the runner's configured policy file
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
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return HostPolicy{}, err
	}
	return ParseHostPolicy(b)
}

// CheckPrefixesOnHost walks every rule's path prefixes on this host from "/"
// with lstat and refuses one that passes through a symlink or a non-directory.
// The target writer opens each component with O_NOFOLLOW, so such a prefix
// would admit a job that is then denied on every write — on macOS /var, /tmp
// and /etc are symlinks into /private. A missing tail is fine: it does not
// exist yet, and the writer still refuses whatever appears there later.
// ParseHostPolicy does not call this: a policy parses without its host.
func CheckPrefixesOnHost(p HostPolicy) error {
	for i, r := range p.Targets {
		for _, pre := range r.PathPrefixes {
			if err := checkPrefixOnHost(pre); err != nil {
				return fmt.Errorf("runnerproto: host policy: rule %d (%s): prefix %q %w", i, r.Kind, pre, err)
			}
		}
	}
	return nil
}

func checkPrefixOnHost(prefix string) error {
	cur := "/"
	for _, seg := range strings.Split(strings.TrimPrefix(prefix, "/"), "/") {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return fmt.Errorf("component %q cannot be checked: %w", cur, err)
		case fi.Mode()&fs.ModeSymlink != 0:
			hint := ""
			if real, err := filepath.EvalSymlinks(cur); err == nil {
				hint = fmt.Sprintf(" (use the real path %q)", filepath.Join(real, strings.TrimPrefix(prefix, cur)))
			}
			return fmt.Errorf("component %q is a symlink%s", cur, hint)
		case !fi.IsDir():
			return fmt.Errorf("component %q is not a directory", cur)
		}
	}
	return nil
}
