package runnerproto

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Journal remembers the job ids a runner has accepted. Claim must be atomic:
// of two concurrent claims of one id exactly one succeeds. An id may be
// forgotten once its job can no longer pass the time check, that is after
// notAfter+ClockSkew.
type Journal interface {
	Claim(jobID string, notAfter, now time.Time) error
}

// MemJournal is an in-memory Journal. It forgets everything on restart, so
// alone it lets a job be replayed after a restart within MaxJobTTL. A runner
// uses FileJournal; MemJournal is for tests and for the file journal's cache.
type MemJournal struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemJournal returns an empty journal.
func NewMemJournal() *MemJournal { return &MemJournal{seen: map[string]time.Time{}} }

// Claim implements Journal.
func (m *MemJournal) Claim(jobID string, notAfter, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.claimLocked(jobID, notAfter, now)
}

func (m *MemJournal) claimLocked(jobID string, notAfter, now time.Time) error {
	for id, exp := range m.seen {
		if now.After(exp.Add(ClockSkew)) {
			delete(m.seen, id)
		}
	}
	if _, dup := m.seen[jobID]; dup {
		return ErrReplay
	}
	m.seen[jobID] = notAfter
	return nil
}

// FileJournal is a Journal that survives restarts: an append-only file of
// "<job id> <not_after unix>" lines, synced before Claim returns. Expired
// lines are dropped when the journal is opened.
type FileJournal struct {
	mu     sync.Mutex
	mem    *MemJournal
	f      *os.File
	broken bool
}

// syncFile is how the journal makes a file durable; a test replaces it to
// see which files are synced, and in what order.
var syncFile = (*os.File).Sync

// OpenFileJournal loads the journal at path, creating it with mode 0600.
//
// A last line without its newline is dropped: a crash between Claim's write
// and its sync can leave one, and that claim never returned success, so no
// job ran on it. Any other unreadable line is damage, and the journal
// refuses to open rather than forget ids.
func OpenFileJournal(path string, now time.Time) (*FileJournal, error) {
	mem := NewMemJournal()
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: path is the runner's own configured journal
		lines := strings.Split(string(b), "\n")
		// The last element follows the final newline: empty for a journal
		// that ended cleanly, otherwise the torn line.
		for _, line := range lines[:len(lines)-1] {
			id, exp, ok := strings.Cut(line, " ")
			n, err := strconv.ParseInt(exp, 10, 64)
			if !ok || err != nil || !uuidV7Re.MatchString(id) {
				return nil, errors.New("runnerproto: replay journal is corrupt")
			}
			if t := time.Unix(n, 0); !now.After(t.Add(ClockSkew)) {
				mem.seen[id] = t
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("runnerproto: read replay journal: %w", err)
	}
	if err := rewriteJournal(path, mem.seen); err != nil {
		return nil, fmt.Errorf("runnerproto: rewrite replay journal: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: see above
	if err != nil {
		return nil, err
	}
	return &FileJournal{mem: mem, f: f}, nil
}

// rewriteJournal replaces the file at path with the live ids, durably: the
// new file is synced before the rename and the directory after it, so a
// power loss leaves either the old journal or the new one, never an empty
// file that has forgotten ids still inside their window.
func rewriteJournal(path string, seen map[string]time.Time) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: see OpenFileJournal
	if err != nil {
		return err
	}
	var sb strings.Builder
	for id, t := range seen {
		fmt.Fprintf(&sb, "%s %d\n", id, t.Unix())
	}
	if _, err := f.WriteString(sb.String()); err != nil {
		_ = f.Close()
		return err
	}
	if err := syncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return syncFile(d)
}

// ErrJournalBroken is returned by every Claim after a write or sync of the
// journal failed: what is on disk is then unknown, so the runner accepts no
// more jobs until it is restarted and the journal reopened.
var ErrJournalBroken = errors.New("runnerproto: replay journal failed; restart the runner")

// Claim implements Journal. The id is on disk before Claim reports success.
func (j *FileJournal) Claim(jobID string, notAfter, now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.mem.mu.Lock()
	defer j.mem.mu.Unlock()
	if j.broken {
		return ErrJournalBroken
	}
	if !uuidV7Re.MatchString(jobID) {
		return invalid("job_id is not a UUIDv7")
	}
	if _, dup := j.mem.seen[jobID]; dup {
		return ErrReplay
	}
	if _, err := fmt.Fprintf(j.f, "%s %d\n", jobID, notAfter.Unix()); err != nil {
		j.broken = true
		return fmt.Errorf("runnerproto: write replay journal: %w", err)
	}
	if err := syncFile(j.f); err != nil {
		j.broken = true
		return fmt.Errorf("runnerproto: sync replay journal: %w", err)
	}
	return j.mem.claimLocked(jobID, notAfter, now)
}

// Close closes the file.
func (j *FileJournal) Close() error { return j.f.Close() }
