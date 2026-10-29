package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// tokenFilePerm is the only mode a token file may be written or read with:
// owner read/write, nothing for group or other.
const tokenFilePerm = 0o600

// resolveToken returns the bearer token to authenticate with. KEEP_TOKEN
// always wins over the file: an operator overriding it for one shell or one
// CI job should never have to touch the file `keep login` maintains.
//
// A token file readable by anyone but its owner is refused outright, never
// silently accepted — see CONTRIBUTING.md: a token is exactly as sensitive
// as a secret value once it exists on disk, and a loose mode usually means
// the file was copied, backed up, or written by a misconfigured deploy
// step, none of which this process can tell apart from a real leak.
//
// Known scope limit: the check below is POSIX permission bits only. A
// filesystem ACL (macOS ACLs, POSIX ACLs on Linux) granting another user
// access alongside an otherwise-correct 0600 mode is not detected. Closing
// it needs the same parent-directory ACL walk internal/targets runs for a
// multi-tenant runner deploying secrets to other principals; this is a
// single-tenant operator CLI reading its own file back under its own
// account, a materially smaller threat, so that machinery is not pulled in
// here — left as a residual gap, a deliberate scope call, not an
// oversight. The symlink half of the original gap is
// closed below (openTokenFileNoFollow): unlike the ACL gap, refusing to
// follow a symlink at open time costs one syscall flag, not a platform ACL
// API, so there was no comparable reason to leave it open.
func resolveToken(getenv func(string) string, path string) (string, error) {
	if t := getenv("KEEP_TOKEN"); t != "" {
		return t, nil
	}
	if path == "" {
		return "", errNoToken
	}
	// The file is opened once and its mode is checked on that same open
	// descriptor (fstat, not stat-then-open-by-path): checking the path and
	// then reopening it by name would leave a window for the path to start
	// pointing somewhere else between the two — the permission guarantee
	// below only means anything if it applies to the bytes actually read.
	f, err := openTokenFileNoFollow(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", errNoToken
		}
		return "", fmt.Errorf("open token file: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat token file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("refusing to read token file: permissions allow access beyond its owner — chmod 600 it or run `keep login` again")
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("token file is empty — run `keep login`")
	}
	return tok, nil
}

var errNoToken = errors.New("no token: set KEEP_TOKEN or pipe a token into `keep login`")

// runLogin writes token to path, creating parent directories as needed, and
// leaves the file at exactly tokenFilePerm. It writes to a temp file in the
// same directory (already at tokenFilePerm, never a looser default) and
// renames it over path, rather than writing path directly and chmod-ing it
// afterward: the latter has a window — however short — where a file holding
// the token exists at the directory's default (often world-readable) mode,
// and os.WriteFile only applies its mode argument when it creates the file,
// so it would silently leave a pre-existing looser-mode file unfixed anyway.
// A same-directory rename is atomic, so a concurrent reader of path never
// observes a partially written file either.
func runLogin(path, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("login: token must not be empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".keep-token-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp token file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds
	if err := tmp.Chmod(tokenFilePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temp token file permissions: %w", err)
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}

// defaultTokenPath is where `keep login` writes and every other command
// reads from when KEEP_TOKEN and --token-file are both unset:
// $XDG_CONFIG_HOME/keep/token, falling back to $HOME/.config/keep/token.
func defaultTokenPath(getenv func(string) string) string {
	if xdg := getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "keep", "token")
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "keep", "token")
	}
	return ""
}
