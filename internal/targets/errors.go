package targets

import (
	"errors"
	"fmt"
)

// ErrPolicy wraps every refusal that is a policy decision, not an I/O
// failure: a symlink or ".." on the path, a directory or target reachable by
// an agent, a hardlink or race caught after opening, an ACL grant on macOS.
// A future caller (internal/runner) maps this to
// runnerproto.ErrClassPolicyDenied.
var ErrPolicy = errors.New("targets: refused by policy")

// ErrWrite wraps every refusal that is an I/O or format failure: the target
// directory does not exist, a write or fsync failed, an external helper
// (systemd-creds) failed, or a structured target (plist, JSON) is malformed
// or missing the key this write depends on. A future caller maps this to
// runnerproto.ErrClassTargetWrite.
var ErrWrite = errors.New("targets: write failed")

// denied formats a policy refusal. Arguments are a path, a field name, an
// owner or a reason — never file content or a secret value.
func denied(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicy, fmt.Sprintf(format, a...))
}

// writeFailed formats an I/O or format refusal. Same rule: no content, no
// value.
func writeFailed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrWrite, fmt.Sprintf(format, a...))
}

// ErrUnconfirmed wraps every failure that happens strictly after Renameat
// has already published new content at the target: the disk now holds v (or
// whatever a racing writer left there instead), but Write could not confirm
// what — the post-rename read-back, a kindHandler's parse of it, or
// fingerprint.Compute failed. It deliberately does NOT wrap ErrWrite: an
// error this constructs never satisfies errors.Is(err, ErrWrite). Every
// existing caller and test reads ErrWrite as "the target was not touched",
// and an ErrUnconfirmed that also satisfied that check would tell a caller
// exactly the opposite of what happened — a runner deciding whether a job
// failed cleanly enough to retry, or a rollback deciding which targets still
// need reverting, would both skip a target that already holds the new
// value. A caller that sees ErrUnconfirmed must treat the target's state as
// unknown and re-verify it before acting again, never retry blind and never
// assume the previous value is still there.
var ErrUnconfirmed = errors.New("targets: write landed but could not be confirmed")

// unconfirmed formats a post-rename confirmation failure. Same rule as
// writeFailed and denied: a class of cause, never file content or a secret
// value — the error it wraps (from readExisting, a kindHandler's readBack,
// or fingerprint.Compute) is already held to that rule elsewhere in this
// package, so folding its text in with %v adds no new leak surface.
func unconfirmed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnconfirmed, fmt.Sprintf(format, a...))
}
