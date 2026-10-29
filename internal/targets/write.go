//go:build unix

package targets

import (
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"golang.org/x/sys/unix"
)

// kindHandler is the per-target-kind adapter over the shared secure-write
// core. build returns the full new content to write; readBack re-derives,
// from that content once it has actually landed on disk, the value at
// t.Field — Result.Fingerprint attests to what the disk holds, not to what
// was in memory before the write.
type kindHandler interface {
	build(existing []byte, exists bool, t runnerproto.Target, v secret.Value) ([]byte, error)
	readBack(content []byte, t runnerproto.Target) (secret.Value, error)
	// foldsExisting: build carries bytes of the existing target into the new
	// one, so the existing target must be one nobody else could have written.
	foldsExisting() bool
}

var kindHandlers = map[runnerproto.TargetKind]kindHandler{
	runnerproto.TargetEnvFile:           envFileHandler{},
	runnerproto.TargetFile:              fileHandler{},
	runnerproto.TargetLaunchdEnv:        launchdEnvHandler{},
	runnerproto.TargetSystemdCredential: systemdCredentialHandler{},
	runnerproto.TargetMCPConfig:         jsonPathHandler{},
	runnerproto.TargetHermesConfig:      hermesEnvHandler{},
}

// computeFingerprint is fingerprint.Compute behind a test seam, same
// convention as fsyncFD/afterRename/afterChmod below: the confirm-phase call
// (after Renameat) can only fail with ErrZeroKey, and only when the
// pre-flight call above already failed with the same key - so no natural
// input reaches that branch. A test overrides this var to reach it anyway
// and prove the confirm-phase error is wrapped as ErrUnconfirmed, not
// whatever class fingerprint.Compute's own error would carry.
var computeFingerprint = fingerprint.Compute

// Option adjusts a Write for what the host's policy allows.
type Option func(*writeOptions)

type writeOptions struct {
	credPlaintext bool
	credNotice    func(path string)
}

// WithSystemdCredPlaintextFallback is how HostPolicy.SystemdCredPlaintextFallback
// reaches the writer: with it, a systemd-credential target on a host without
// systemd-creds is written as a plain 0600 file, whatever mode the target asks for; without it
// (the default) such a target is refused as a policy denial and nothing is
// written. notice, if not nil, is called with the target's path each time the
// plaintext fallback is actually used, so the runner can log it (never with
// the value); Result carries no field for that.
func WithSystemdCredPlaintextFallback(notice func(path string)) Option {
	return func(o *writeOptions) { o.credPlaintext, o.credNotice = true, notice }
}

// Write securely writes v into t (ADR-001 §3.2, Appendix C.5). agentUIDs
// and agentGIDs are the agent uids/gids on this host (HostPolicy); the write
// is refused if the target, or any directory on its path, would be
// reachable by one of them. fpKey computes the kfp1 fingerprint of the value
// once written, read back from the target — see package doc.
//
// This does not re-run runnerproto.HostPolicy.Check: the caller (the future
// internal/runner) is expected to have already checked the job against the
// host's policy before ever building a Target for Write. What Write adds on
// top is a check against the filesystem's own current state, which a
// declarative policy check over the job's fields cannot see — and, as its
// first step, Target.Validate, so a malformed target is refused whatever the
// caller did before.
//
// An error wrapping ErrUnconfirmed (as opposed to ErrWrite or ErrPolicy)
// means Renameat has already published new content at t.Path — the target
// is not untouched, whatever the error text says. The caller must treat the
// target's state as unknown and re-verify it, not retry the write blind or
// assume the previous value is still there. See errors.go.
func Write(t runnerproto.Target, v secret.Value, agentUIDs, agentGIDs []int64, fpKey fingerprint.Key, opts ...Option) (string, error) {
	// First, before anything touches the filesystem: a Field or Unit that is
	// not the shape its kind takes (an XML fragment for launchd-env, a line
	// break for env-file) must be refused while nothing has been read or
	// written, not after a half-built file exists.
	if err := t.Validate(); err != nil {
		return "", denied("%v", err)
	}
	h, ok := kindHandlers[t.Kind]
	if !ok {
		return "", denied("unknown target kind %q", t.Kind)
	}
	var o writeOptions
	for _, opt := range opts {
		opt(&o)
	}
	var fellBack bool
	if t.Kind == runnerproto.TargetSystemdCredential {
		h = systemdCredentialHandler{plaintextFallback: o.credPlaintext, usedFallback: &fellBack}
	}
	// The fingerprint is computed from the disk after the write; a key that
	// cannot compute one must fail now, not after the value has landed.
	if _, err := computeFingerprint(fpKey, secret.New([]byte{0})); err != nil {
		return "", writeFailed("fingerprint key is unusable: %v", err)
	}
	ag := agentSet{uids: agentUIDs, gids: agentGIDs}
	if err := validateTargetPerm(t.Mode, t.UID, t.GID, ag); err != nil {
		return "", err
	}

	parentFD, base, err := walkToParent(t.Path, ag)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(parentFD) }()

	owners := []int64{int64(unix.Geteuid()), t.UID}
	existing, exists, err := readExisting(parentFD, base, t.Path, owners, ag, h.foldsExisting())
	if err != nil {
		return "", err
	}
	defer wipe(existing)

	content, err := h.build(existing, exists, t, v)
	if err != nil {
		return "", err
	}
	defer wipe(content)

	// A plaintext fallback file is never wider than 0600, whatever mode the
	// target asked for: the sealed form it replaces would not have been
	// readable by the group either.
	mode := t.Mode
	if fellBack {
		mode = 0o600
	}
	if err := secureCreateAndWrite(parentFD, base, mode, t.UID, t.GID, content); err != nil {
		return "", err
	}
	if fellBack && o.credNotice != nil {
		o.credNotice(t.Path)
	}

	// Renameat has now succeeded (inside secureCreateAndWrite): the target
	// holds new content, whatever happens from here. Every error below is
	// reclassified as ErrUnconfirmed rather than passed through as whatever
	// class its source would naturally carry — reporting ErrWrite (or a bare
	// readBack error that itself wraps ErrWrite) past this point would tell
	// the caller the target was untouched, which is now false. See
	// ErrUnconfirmed's doc comment in errors.go.
	written, _, err := readExisting(parentFD, base, t.Path, owners, ag, false)
	if err != nil {
		return "", unconfirmed("read back target after write: %v", err)
	}
	defer wipe(written)

	back, err := h.readBack(written, t)
	if err != nil {
		return "", unconfirmed("parse written target: %v", err)
	}
	defer back.Wipe()

	fp, err := computeFingerprint(fpKey, back)
	if err != nil {
		return "", unconfirmed("compute fingerprint: %v", err)
	}
	return fp, nil
}

// A var, not a plain func, only so TestBuildWipesIntermediateJSONBuffers can
// wrap it to record which slices actually got zeroed — proving build's own
// intermediate JSON copies are among them, not just that wipe exists and is
// called somewhere.
var wipe = func(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// bytesOf copies v's bytes out into an owned slice. Every caller wipes what
// it gets back once it is done with it.
func bytesOf(v secret.Value) []byte {
	out := make([]byte, v.Len())
	secret.Expose(v, func(b []byte) { copy(out, b) })
	return out
}
