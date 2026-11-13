//go:build !unix

package runnerproto

import (
	"errors"
	"os"
)

var errJournalNotRegular = errors.New("runnerproto: replay journal is not a regular file")

// readJournal returns the bytes of an existing journal. Without O_NONBLOCK
// and O_NOFOLLOW the type is checked by Lstat before the read; the runner
// itself is unix-only, so this is a best-effort build fallback.
func readJournal(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errJournalNotRegular
	}
	return os.ReadFile(path) //nolint:gosec // G304: path is the runner's own configured journal
}
