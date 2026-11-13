//go:build unix

package runnerproto

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// errJournalNotRegular is the static refusal for a journal path that is not
// an ordinary file. It carries neither the path nor any content.
var errJournalNotRegular = errors.New("runnerproto: replay journal is not a regular file")

// readJournal returns the bytes of an existing journal. The open is
// non-blocking (O_NONBLOCK) so a FIFO without a writer planted at the path
// returns at once and is refused by the regular-file check on the same fd,
// instead of hanging in open(2) before any type check; O_NOFOLLOW refuses a
// symlink; O_NOCTTY keeps a tty from becoming the controlling terminal.
// O_NONBLOCK has no effect on reads of a regular file. A missing file
// reports os.ErrNotExist.
func readJournal(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) //nolint:gosec // G304: path is the runner's own configured journal
	if errors.Is(err, syscall.ELOOP) {                                                                 // O_NOFOLLOW met a symlink
		return nil, errJournalNotRegular
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errJournalNotRegular
	}
	return io.ReadAll(f)
}
