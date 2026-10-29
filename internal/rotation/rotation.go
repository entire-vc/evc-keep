// Package rotation runs a two-phase secret rotation: a new version is created,
// laid out on every carrier, verified (fingerprint and health) on every
// carrier, and only then is the old version revoked. Anything short of 100%
// verified carriers leaves the old version alone and opens an incident.
//
// The engine knows no value. Everything it stores or passes is an id, a
// version label, a state name, a fingerprint or a closed error class. The
// collaborators are interfaces declared here; the real deployer, verifier and
// revoker are wired by the caller.
package rotation

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type State string

const (
	StateNewVersion  State = "new_version"
	StateDeploying   State = "deploying"
	StateVerifying   State = "verifying"
	StateRevokingOld State = "revoking_old"
	StateDone        State = "done"
	StateFailed      State = "failed"
)

// Class is the closed set of failure reasons a run may record.
type Class string

const (
	ClassNone                Class = ""
	ClassNoCarriers          Class = "no_carriers"
	ClassDeployFailed        Class = "deploy_failed"
	ClassFingerprintMismatch Class = "fingerprint_mismatch"
	ClassUnhealthy           Class = "unhealthy"
	ClassVerifyFailed        Class = "verify_failed"
	ClassRevokeFailed        Class = "revoke_failed"
	ClassPrepareFailed       Class = "prepare_failed"
	// ClassSuperseded: a human sealed a newer version while the run was laying
	// its own out; the run ends without activating anything, the newer version
	// has its own run, and the record of what is deployed does not move.
	ClassSuperseded    Class = "superseded"
	ClassInternalError Class = "internal_error"
	// ClassOriginalKeyUnknown: the run is done, but the provider key that stood
	// behind the old version was not known, so it was not revoked.
	ClassOriginalKeyUnknown Class = "original_key_unknown"
	// ClassRollbackUnconfirmed: a failed prepare could not confirm that the new
	// key it had issued was ended.
	ClassRollbackUnconfirmed Class = "rollback_unconfirmed"
	// ClassPolicyDenied is reported, never stored in a run: the approval a
	// prod rotation waited for was rejected or expired, so no run exists. It
	// reads as permission_denied, the class a refused deployment approval has.
	ClassPolicyDenied Class = "permission_denied"
)

var (
	// ErrConflict: another run of the same secret is active.
	ErrConflict = errors.New("rotation: another run of this secret is active")
	// ErrFailed: the run ended in failed; the old version was not revoked.
	ErrFailed = errors.New("rotation: run failed")
	// ErrRevokePending: every carrier holds the new version but the old one
	// could not be revoked. The run stays in revoking_old (class revoke_failed),
	// the "old key alive" incident is open, and Rotate with the same run id
	// retries the revoke only.
	ErrRevokePending = errors.New("rotation: old version not revoked yet")
	// ErrLeaseLost: this call no longer holds the run's lease (another
	// caller took it over); it stopped without touching the old version.
	ErrLeaseLost = errors.New("rotation: lease lost")
	// ErrUnavailable: the approval or the journal could not be reached; nothing
	// was started.
	ErrUnavailable = errors.New("rotation: unavailable")
	// ErrPreparedProd: a prod secret takes no ready-made version; its rotation
	// goes through an approval. Nothing was written.
	ErrPreparedProd = errors.New("rotation: a prod secret rotates through an approval")
	// ErrNotFound: the run id belongs to a different secret or organization.
	ErrNotFound = errors.New("rotation: run unavailable")
	// ErrIncident: the incident could not be recorded or resolved; the cause is not
	// forwarded, a collaborator's error text is never returned.
	ErrIncident = errors.New("rotation: incident not recorded")
	// ErrInvalid: a collaborator returned something that is not metadata.
	ErrInvalid = errors.New("rotation: invalid collaborator output")
)

// Ref names the secret being rotated.
type Ref struct {
	OrgID    uuid.UUID
	SecretID uuid.UUID
}

// Carrier is an opaque carrier id; the engine never looks inside.
type Carrier struct{ ID string }

// Version is what Prepare returns: the old and new version labels and the
// fingerprint every carrier must report for the new one.
type Version struct {
	Old         string
	New         string
	Fingerprint string
	// Length is the byte length of the new value, for the journal; 0 means
	// not known (a resumed run reads its version back from the ledger).
	Length int
}

// Report is what a carrier says about itself after a layout.
type Report struct {
	Fingerprint string
	Healthy     bool
}

// Contract for every collaborator interface below: IDs and versions carry no
// value. A carrier id is a canonical lowercase UUID and a version is a plain
// decimal integer (see labels.go); the engine refuses anything else before it
// reaches a store, a result, an incident or an error, but a UUID-shaped value
// passes the grammar, so the contract still binds the collaborator: it must
// never put a secret value, or text derived from one, into an id, a version
// or an error it returns.

// Versions creates the new version. It must be idempotent per runID: a
// resumed run calls it again and must get the same version back.
type Versions interface {
	Prepare(ctx context.Context, ref Ref, runID uuid.UUID) (Version, error)
}

// Adopter is the optional half of Versions for a version that already exists
// (a human entered the value). Adopt only checks the version and resolves what
// the revoke step will need; it writes nothing. The returned write records the
// version under the run, so that the later steps and a resumed run find it as
// they find a prepared one. The caller runs the write in the transaction that
// creates the run: the record and the run stand or fall together. Idempotent
// per runID.
type Adopter interface {
	Adopt(ctx context.Context, ref Ref, runID uuid.UUID, v Version) (AdoptWrite, error)
}

// AdoptWrite records an adopted version inside the caller's transaction.
type AdoptWrite func(ctx context.Context, tx pgx.Tx) error

// Superseder is the optional half of Versions that retires a version no run
// will lay out: a human entered a newer value before this one got its layout.
// Idempotent; an unknown version is not an error.
type Superseder interface {
	Supersede(ctx context.Context, ref Ref, version string) error
}

// Carriers lists the carriers of a secret.
type Carriers interface {
	List(ctx context.Context, ref Ref) ([]Carrier, error)
}

// Deployer lays the new version out on one carrier. Idempotent per
// (runID, carrier). The carrier id and version carry no value.
//
// Fencing: the ownership check before the call cannot make the call atomic, a
// caller can stall between the two for longer than its lease. The context of
// every Deploy and Revoke therefore ends with the caller's lease and carries
// its epoch (Epoch(ctx)); a Deployer or Revoker that changes anything outside
// this database must refuse a call whose epoch is lower than one it has
// already accepted for the same secret.
type Deployer interface {
	Deploy(ctx context.Context, ref Ref, runID uuid.UUID, c Carrier, version string) error
}

// Verifier reads the carrier back: fingerprint and health. The carrier id and
// version carry no value.
type Verifier interface {
	Verify(ctx context.Context, ref Ref, c Carrier, version string) (Report, error)
}

// Revoker retires the old version. Idempotent per (runID, oldVersion): a run
// that died mid-revoke calls it again. The old version carries no value.
type Revoker interface {
	Revoke(ctx context.Context, ref Ref, runID uuid.UUID, oldVersion string) error
}

// DeployedMarker is the optional half of Revoker that records which version is
// laid out: called once every carrier has confirmed the new version, before the
// old one is revoked, and also when there is no old version to revoke. Idempotent;
// it never moves the record to an older version.
type DeployedMarker interface {
	MarkDeployed(ctx context.Context, ref Ref, runID uuid.UUID, version string) error
}

// SupersedeChecker is the optional half of Versions that tells whether a version
// sealed after the given one is still enabled.
type SupersedeChecker interface {
	NewerSealed(ctx context.Context, ref Ref, version string) (bool, error)
}

// IncidentRecord carries ids and classes only; ids carry no value.
type IncidentRecord struct {
	Ref      Ref
	RunID    uuid.UUID
	Class    Class
	Carriers []string // carrier ids that did not pass
	// ForwardOnly: the provider ended the old key when it issued the new one,
	// so there is no rollback and the carriers listed are to be laid out again.
	ForwardOnly bool
}

// Incident writes the journal entry and fires the hook. Idempotent per RunID;
// like the Deployer it is called with the lease epoch (Epoch(ctx)) and refuses
// a call whose epoch is lower than one it already accepted for the run.
type Incident interface {
	Open(ctx context.Context, rec IncidentRecord) error
	// Resolve closes the incident Open recorded for rec.RunID and rec.Class,
	// once the condition is gone (the old key was revoked on a retry). Same
	// fencing and idempotency as Open; resolving what was never opened is an
	// error.
	Resolve(ctx context.Context, rec IncidentRecord) error
}

type Options struct {
	// RunID is the idempotency key: the same id resumes or replays the run.
	// Zero means a fresh random run.
	RunID uuid.UUID
	// Concurrency bounds simultaneous layouts and verifications (default 4).
	Concurrency int
	// LeaseTTL is how long a crashed run blocks others (default 5 minutes).
	LeaseTTL time.Duration
	// DeployAttempts and RetryDelay bound the layout retries of a forward-only
	// run (defaults 4 and 2s). A provider with a second valid key gets one
	// attempt: a failed layout fails the run and nothing is revoked.
	DeployAttempts int
	RetryDelay     time.Duration
}

type Result struct {
	RunID       uuid.UUID
	State       State
	OldVersion  string
	NewVersion  string
	Fingerprint string
	Class       Class
}
