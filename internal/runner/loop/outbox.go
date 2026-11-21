package loop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// The outbox is a directory of one file per job, "<job_id>.json", mode 0600
// in a 0700 directory. A file holds the job id, its state and, once closed,
// the closed Result: names and classes only, never a value.
const (
	stateStarted = "started"
	stateClosed  = "closed"
	maxEntrySize = 64 << 10
	// maxDiscoverEntrySize bounds a discover entry: the largest report the
	// contract allows stays below it: MaxDiscoverFindings findings, each with a
	// 1 KiB path and a 128-char name of characters json.Marshal expands to six
	// bytes (<, >, &), about 29 MB. Write and read use the same
	// cap, so a stored entry is never one List refuses.
	maxDiscoverEntrySize = 32 << 20
)

var jobIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Outbox is the runner's durable record of jobs in flight and of results the
// server has not acknowledged.
type Outbox struct{ dir string }

// kindDiscover marks an entry of a discover job: its closed outcome is a
// DiscoverResult, never a Result.
const kindDiscover = "discover"

type entry struct {
	JobID    string           `json:"job_id"`
	State    string           `json:"state"`
	Kind     string           `json:"kind,omitempty"`
	Result   *json.RawMessage `json:"result,omitempty"`
	Discover *json.RawMessage `json:"discover,omitempty"`
}

// Pending is one outbox entry read back. A discover job has IsDiscover set
// and, once closed, its report in Discover; Result is then zero.
type Pending struct {
	JobID      string
	Closed     bool
	IsDiscover bool
	Result     runnerproto.Result
	Discover   runnerproto.DiscoverResult
}

// OpenOutbox creates dir (0700) if needed and refuses a symlink, a
// non-directory or one owned by another user.
func OpenOutbox(dir string) (*Outbox, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return nil, errors.New("loop: outbox directory")
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("loop: outbox directory")
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o700 || !ownedByUs(fi) {
		return nil, errors.New("loop: outbox directory is not a private directory")
	}
	return &Outbox{dir: dir}, nil
}

func (o *Outbox) path(jobID string) (string, error) {
	if !jobIDRe.MatchString(jobID) {
		return "", errors.New("loop: outbox job id")
	}
	return filepath.Join(o.dir, jobID+".json"), nil
}

// Begin records that the job was accepted and is about to run. It is durable
// before the value is requested.
func (o *Outbox) Begin(jobID string) error { return o.write(jobID, stateStarted, "", nil, true) }

// BeginDiscover is Begin for a discover job, so a restart closes it with a
// failed DiscoverResult rather than a Result.
func (o *Outbox) BeginDiscover(jobID string) error {
	return o.write(jobID, stateStarted, kindDiscover, nil, true)
}

// CloseDiscover records a discover job's closed report. It refuses a report
// outside the contract.
func (o *Outbox) CloseDiscover(jobID string, r runnerproto.DiscoverResult) error {
	return o.closeDiscover(jobID, r, false)
}

// CloseDiscoverIfAbsent is CloseDiscover that never replaces an entry.
func (o *Outbox) CloseDiscoverIfAbsent(jobID string, r runnerproto.DiscoverResult) error {
	return o.closeDiscover(jobID, r, true)
}

func (o *Outbox) closeDiscover(jobID string, r runnerproto.DiscoverResult, exclusive bool) error {
	if err := r.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	raw := json.RawMessage(b)
	return o.write(jobID, stateClosed, kindDiscover, &raw, exclusive)
}

// Close records the job's closed Result. It replaces a started entry and
// refuses a Result outside the contract.
func (o *Outbox) Close(jobID string, r runnerproto.Result) error {
	return o.close(jobID, r, false)
}

// CloseIfAbsent is Close for a job that never started: it refuses to replace
// any existing entry, so a job that already ran cannot have its Result
// overwritten by a later rejection of the same signed job.
func (o *Outbox) CloseIfAbsent(jobID string, r runnerproto.Result) error {
	return o.close(jobID, r, true)
}

func (o *Outbox) close(jobID string, r runnerproto.Result, exclusive bool) error {
	if err := r.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	raw := json.RawMessage(b)
	return o.write(jobID, stateClosed, "", &raw, exclusive)
}

// Ack removes the entry once the server acknowledged the Result (or refused
// it for good).
func (o *Outbox) Ack(jobID string) error {
	p, err := o.path(jobID)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("loop: outbox remove")
	}
	return nil
}

// write stores one entry. A discover entry keeps its report under "discover",
// any other under "result".
func (o *Outbox) write(jobID, state, kind string, result *json.RawMessage, exclusive bool) error {
	p, err := o.path(jobID)
	if err != nil {
		return err
	}
	if exclusive {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("loop: outbox entry exists: %w", os.ErrExist)
		}
	}
	e := entry{JobID: jobID, State: state, Kind: kind}
	if kind == kindDiscover {
		e.Discover = result
	} else {
		e.Result = result
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) > entryCap(kind) {
		return errors.New("loop: outbox entry too large")
	}
	tmp, err := os.CreateTemp(o.dir, ".tmp-outbox-*")
	if err != nil {
		return errors.New("loop: outbox write")
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return errors.New("loop: outbox write")
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return errors.New("loop: outbox write")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.New("loop: outbox write")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("loop: outbox write")
	}
	if err := os.Rename(tmpPath, p); err != nil {
		return errors.New("loop: outbox write")
	}
	return syncDir(o.dir)
}

// List reads every entry, oldest name first. An entry that is not a regular
// 0600 file of this user, is oversized, malformed or carries a Result outside
// the contract is an error: the outbox is the runner's own state, and damage
// to it is not guessed around.
func (o *Outbox) List() ([]Pending, error) {
	ents, err := os.ReadDir(o.dir)
	if err != nil {
		return nil, errors.New("loop: outbox read")
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	var out []Pending
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".tmp-outbox-") {
			continue
		}
		id, ok := strings.CutSuffix(name, ".json")
		if !ok || !jobIDRe.MatchString(id) {
			return nil, errors.New("loop: unexpected file in outbox")
		}
		p, err := o.read(id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (o *Outbox) read(jobID string) (Pending, error) {
	bad := errors.New("loop: outbox entry is damaged")
	p, err := o.path(jobID)
	if err != nil {
		return Pending{}, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|noFollow, 0) //nolint:gosec // G304: p is built from a validated job id under the runner's own outbox
	if err != nil {
		return Pending{}, bad
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || !ownedByUs(fi) {
		return Pending{}, bad
	}
	// The kind is not known before decoding, so read up to the larger cap and
	// check the entry's own cap after it.
	b, err := io.ReadAll(io.LimitReader(f, maxDiscoverEntrySize+1))
	if err != nil || len(b) > maxDiscoverEntrySize {
		return Pending{}, bad
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var e entry
	if err := dec.Decode(&e); err != nil || dec.More() || e.JobID != jobID {
		return Pending{}, bad
	}
	switch {
	case len(b) > entryCap(e.Kind):
		return Pending{}, bad
	case e.Kind != "" && e.Kind != kindDiscover:
		return Pending{}, bad
	case e.State == stateStarted && e.Result == nil && e.Discover == nil:
		return Pending{JobID: jobID, IsDiscover: e.Kind == kindDiscover}, nil
	case e.State == stateClosed && e.Kind == kindDiscover && e.Discover != nil && e.Result == nil:
		r, err := runnerproto.DecodeDiscoverResult(*e.Discover)
		if err != nil {
			return Pending{}, bad
		}
		return Pending{JobID: jobID, Closed: true, IsDiscover: true, Discover: r}, nil
	case e.State == stateClosed && e.Kind == "" && e.Result != nil && e.Discover == nil:
		r, err := runnerproto.DecodeResult(*e.Result)
		if err != nil {
			return Pending{}, bad
		}
		return Pending{JobID: jobID, Closed: true, Result: r}, nil
	}
	return Pending{}, fmt.Errorf("%w", bad)
}

// entryCap is the size limit of an entry of the given kind.
func entryCap(kind string) int {
	if kind == kindDiscover {
		return maxDiscoverEntrySize
	}
	return maxEntrySize
}
