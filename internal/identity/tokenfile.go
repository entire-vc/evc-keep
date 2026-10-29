package identity

import (
	"os"
	"path/filepath"
)

// WriteTokenFile writes t and a newline to a new file at dest, mode 0600, the
// one way a token's text reaches disk. It takes a path rather than a writer
// so the text cannot be routed to stdout, a log or a response from outside
// this package. The file is written as a temp file in dest's directory and
// linked into place: link(2) fails when dest exists, so an existing file is
// never overwritten, and dest never holds a partial token.
func WriteTokenFile(dest string, t Token) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".keep-token-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.WriteString(Reveal(t) + "\n"); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	return os.Link(tmp.Name(), dest)
}
