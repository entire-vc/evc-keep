package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/config"
	"github.com/entire-vc/evc-keep/internal/restart"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider/svctoken"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// svcTokenName is the secret name of the Mesh service token in the sealed store.
const svcTokenName = "mesh-service-token"

// maxBootstrapFile bounds what is read from the bootstrap file.
const maxBootstrapFile = 4096

// errBootstrap carries no text of the file or the path.
var errBootstrap = errors.New("mesh service token bootstrap refused")

// wireSelfRotate starts the background rotation of the Mesh service token. It
// does nothing unless KEEP_MESH_SELF_ROTATE=1 or seal-only is configured. The
// token is sealed in the organisation's own store; the rotation itself is the
// plugin's: a build without one stops the start instead of ignoring the
// configuration, seal-only included.
func wireSelfRotate(ctx context.Context, cfg config.Config, opts Options, local *builtin.Local, queue *restart.Repo, logger *slog.Logger) error {
	sr := cfg.MeshSelfRotate
	if !sr.Enabled && !sr.SealOnly {
		return nil
	}
	if opts.SelfRotate == nil {
		return errors.New("mesh service token self-rotation is configured (KEEP_MESH_SELF_ROTATE or KEEP_MESH_SVC_BOOTSTRAP_FILE) but this build has no Mesh plugin")
	}
	prov := local.Provider(sr.OrgID, "", "", "")
	store, err := selfRotateStore(prov, logger)
	if err != nil {
		return err
	}
	return startSelfRotate(ctx, sr, opts, store, queue, prov.FingerprintKey, logger)
}

// selfRotateStore keeps the token in the organization's builtin store. The
// provider goes in unwrapped: a wrapper would hide its Erase, and each
// rotation would leave a sealed staged copy of the live token behind.
func selfRotateStore(prov *builtin.Provider, logger *slog.Logger) (*svctoken.Store, error) {
	store, err := svctoken.New(prov, svcTokenName)
	if err != nil {
		return nil, errors.New("mesh service token store refused its configuration")
	}
	logStagedLeft(store, logger)
	return store, nil
}

// logStagedLeft logs a staged copy Activate could not drop as a class only:
// the provider's error text stays out of the log.
func logStagedLeft(store *svctoken.Store, logger *slog.Logger) {
	store.OnStagedLeft(func(error) {
		logger.Warn("mesh service token staged copy not erased", "error_class", "staged_cleanup")
	})
}

// startSelfRotate seals the bootstrap token and, unless seal-only, starts the
// rotation loop. Seal-only builds no rotation, so nothing calls Mesh and no
// hook runs.
func startSelfRotate(ctx context.Context, sr config.MeshSelfRotate, opts Options, store *svctoken.Store, queue *restart.Repo, fpKey func(context.Context) (fingerprint.Key, error), logger *slog.Logger) error {
	if err := bootstrapSvcToken(ctx, store, sr.BootstrapFile, fpKey, logger); err != nil {
		return err
	}
	if sr.SealOnly {
		logger.Info("mesh service token seal-only: rotation off")
		return nil
	}
	restarts, err := bindRestarts(sr, queue, store, fpKey)
	if err != nil {
		return err
	}
	rotate, err := opts.SelfRotate(sr, store, restarts, logger)
	if err != nil || rotate == nil {
		// The plugin's own text is not printed: it is not Keep's to vouch for.
		return errors.New("mesh service token self-rotation was refused by the Mesh plugin")
	}
	every := sr.Interval
	if opts.SelfRotateEvery > 0 {
		every = opts.SelfRotateEvery
	}
	go runSelfRotate(ctx, every, rotate, logger)
	return nil
}

// bindRestarts is the queue the plugin gets: nil when no lane is configured, an
// error when the lane is not on the queue's allowlist, so a wrong lane stops
// the start instead of the first rotation.
func bindRestarts(sr config.MeshSelfRotate, queue *restart.Repo, store *svctoken.Store, fpKey func(context.Context) (fingerprint.Key, error)) (SelfRotateRestarts, error) {
	if sr.RestartLane == "" {
		return nil, nil
	}
	org, err := uuid.Parse(sr.OrgID)
	if err != nil || !queue.Allows(sr.RestartLane) {
		return nil, errors.New("KEEP_MESH_SELF_ROTATE_RESTART_LANE is not on the restart allowlist")
	}
	return &selfRotateRestarts{queue: queue, org: org, lane: sr.RestartLane, store: store, fpKey: fpKey}, nil
}

// selfRotateRestarts binds the restart queue to the self-rotation's
// organization and lane.
type selfRotateRestarts struct {
	queue *restart.Repo
	org   uuid.UUID
	lane  string
	store SelfRotateStore
	fpKey func(context.Context) (fingerprint.Key, error)
}

// Enqueue asks for a restart of the lane after keyVersion became active. The
// request carries the kfp1 fingerprint of the active token, so the poller and
// the journal can tell which key the lane must be running; the value itself
// goes no further than the digest.
func (q *selfRotateRestarts) Enqueue(ctx context.Context, keyVersion string) (uuid.UUID, error) {
	tok, err := q.store.Token(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	v := secret.New([]byte(tok))
	defer v.Wipe()
	// The fingerprint key is the organization's own, read per call.
	key, err := q.fpKey(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer key.Wipe()
	fp, err := fingerprint.Compute(key, v)
	if err != nil {
		return uuid.Nil, err
	}
	return q.queue.Enqueue(ctx, q.org, q.lane, keyVersion, fp)
}

// Outcome implements SelfRotateRestarts.
func (q *selfRotateRestarts) Outcome(ctx context.Context, id uuid.UUID) (applied, final bool, err error) {
	return q.queue.Outcome(ctx, q.org, id)
}

// bootstrapSvcToken seals the token from path when the store holds none.
// An empty path does nothing. The file is read and left in place, and only the
// secret's name, version, fingerprint and length are logged.
func bootstrapSvcToken(ctx context.Context, store *svctoken.Store, path string, fpKey func(context.Context) (fingerprint.Key, error), logger *slog.Logger) error {
	if path == "" {
		return nil
	}
	// A sealed token needs no file: after the operator deletes it the next
	// start must not fail on the configured path.
	has, err := store.Has(ctx)
	if err != nil {
		logger.Error("mesh service token bootstrap failed", "error_class", "unavailable")
		return errBootstrap
	}
	if has {
		return nil
	}
	v, err := readBootstrapFile(path)
	if err != nil {
		logger.Error("mesh service token bootstrap refused", "error_class", "bootstrap_file")
		return err
	}
	defer v.Wipe()
	key, err := fpKey(ctx)
	if err != nil {
		logger.Error("mesh service token bootstrap failed", "error_class", "unavailable")
		return errBootstrap
	}
	defer key.Wipe()
	fp, err := fingerprint.Compute(key, v)
	if err != nil {
		logger.Error("mesh service token bootstrap failed", "error_class", "unavailable")
		return errBootstrap
	}
	meta, sealed, err := store.Seed(ctx, v)
	if err != nil {
		logger.Error("mesh service token bootstrap failed", "error_class", "unavailable")
		return errBootstrap
	}
	if sealed {
		// In the message, not in attributes: the logger's key set is closed and
		// stays so. Every part is a name, a version label, a kfp1 fingerprint or a count.
		logger.Info(fmt.Sprintf("mesh service token sealed from bootstrap file: name=%s version=%s fingerprint=%s length=%d",
			svcTokenName, meta.Version, fp, meta.Length))
	}
	return nil
}

// readBootstrapFile reads a regular, non-empty file of mode 0600 that is not a
// symlink. The checks are made on the open descriptor, not on the path.
func readBootstrapFile(path string) (secret.Value, error) {
	// O_NONBLOCK: a FIFO in the path must fail the check below, not hang the start.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the operator's own KEEP_MESH_SVC_BOOTSTRAP_FILE.
	if err != nil {
		return secret.Value{}, errBootstrap
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		return secret.Value{}, errBootstrap
	}
	if fi.Size() > maxBootstrapFile {
		return secret.Value{}, errBootstrap
	}
	// One allocation of the exact size: a growing buffer would leave earlier
	// copies of the token on the heap.
	raw := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, raw); err != nil {
		clear(raw)
		return secret.Value{}, errBootstrap
	}
	tok := bytes.TrimSpace(raw)
	if len(tok) == 0 {
		clear(raw)
		return secret.Value{}, errBootstrap
	}
	// secret.New takes ownership of the slice; the untrimmed copy is wiped.
	v := secret.New(append([]byte(nil), tok...))
	clear(raw)
	return v, nil
}

// ErrSelfRotatePending is what a rotation returns while the restart it queued
// has no outcome yet: not a failure, but a reason to look again soon.
var ErrSelfRotatePending = errors.New("mesh service token rotation: restart outcome pending")

// restartCheckEvery is how soon a pending restart is looked at again. It is far
// inside the grace window the plugin asks for with the queue (1200 s), so an
// acknowledged restart ends the old token, and a failed or expired one is
// reported, while the old token still works.
var restartCheckEvery = time.Minute

// runSelfRotate calls rotate every interval until ctx ends. A failure is logged
// by class and the next tick tries again: the loop never stops on an error, and
// the error text is not forwarded. While a queued restart is pending the next
// call comes after restartCheckEvery instead of a whole interval.
func runSelfRotate(ctx context.Context, every time.Duration, rotate func(context.Context) error, logger *slog.Logger) {
	retry := min(every/4, maxRetryDelay)
	wait := every
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = every
		// A failed or orphaned rotation is retried soon rather than a whole
		// interval later: the old token's grace window is short.
		for attempt := 0; ; attempt++ {
			err := rotate(ctx)
			if err == nil {
				break
			}
			if errors.Is(err, ErrSelfRotatePending) {
				wait = min(every, restartCheckEvery)
				break
			}
			logger.Warn("mesh service token rotation failed", "error_class", "rotation")
			if attempt == maxRetries {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
		}
	}
}

const (
	maxRetries    = 4
	maxRetryDelay = 30 * time.Second
)
