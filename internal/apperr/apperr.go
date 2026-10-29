// Package apperr is the one shape an error takes once it leaves the
// process: a class, a message template, and the request id that ties it
// back to a log line — see the threat model's §4.3 closed field list.
//
// message is a template naming things, never a raw wrapped error's own
// text: a provider or OS error may itself contain something that
// shouldn't leave the process (a path, a connection detail), so it is
// logged locally where useful and never forwarded verbatim into an
// Error's Message.
package apperr

// Class is a closed, stable name for an error's kind. It is the only part
// of an error a caller should ever branch on.
type Class string

const (
	// ClassInternal covers everything unexpected: a recovered panic, an
	// unhandled failure mode. Never blame the caller for this one.
	ClassInternal Class = "internal"
	// ClassInvalidArgument covers a request that fails validation before
	// any side effect happens.
	ClassInvalidArgument Class = "invalid_argument"
	// ClassNotReady covers a dependency (currently: the database) not
	// being reachable yet.
	ClassNotReady Class = "not_ready"
	// ClassUnauthenticated is the one class every authentication failure
	// returns to the client — missing header, malformed token, unknown
	// token, expired, revoked. They are indistinguishable on the wire by
	// design; the specific reason is for a local debug log only, never
	// for the caller.
	ClassUnauthenticated Class = "unauthenticated"
	// ClassNotFound covers both "no such resource" and "resource exists
	// but the caller's org_id doesn't match" — the same response for both
	// on purpose, so a mismatched org_id in a URL can never be used to
	// probe whether a resource exists in someone else's organization
	// (404, not 403).
	ClassNotFound Class = "not_found"

	// ClassSecretNotFound is returned by internal/tenancy.Resolve and
	// internal/catalog for "no such name", "exists, but outside this
	// principal's reach" (tenancy model §3 step 4), and — through
	// internal/catalog.ResolveAuthorized — "exists and reachable, but the
	// principal has no rights there" (§3 step 5). All three cases
	// are indistinguishable on purpose, so neither the class nor the
	// message may ever differ between them (that difference would itself
	// be the oracle).
	ClassSecretNotFound Class = "secret_not_found"
	// ClassOverrideLocked is returned when a create or a class/name
	// definition is rejected by an OverrideLock above it (tenancy model
	// §3, §7 scenarios C1/C5).
	ClassOverrideLocked Class = "override_locked"
	// ClassNoStoreBound is returned by catalog.CreateRef when no
	// StoreBinding exists at the target scope or any ancestor (tenancy
	// model §3, §7 scenario C2).
	ClassNoStoreBound Class = "no_store_bound"
	// ClassAmbiguousContext is returned when a principal belongs to more
	// than one workspace (or project) in the org and the request did not
	// say which one — resolution never guesses (tenancy model §7 scenario
	// C3).
	ClassAmbiguousContext Class = "ambiguous_context"
	// ClassAlreadyExists is returned when a create is refused because a
	// unique constraint already holds the row it would have inserted (a
	// name already defined at this scope, a scope that already has a store
	// binding, ...) — including when that constraint is what a concurrent
	// racing create actually lost to: internal/catalog classifies the raw
	// database error into this instead of letting it leave the process as
	// an unclassified one.
	ClassAlreadyExists Class = "already_exists"
	// ClassPermissionDenied is returned when an authenticated, correctly
	// scoped principal lacks the permission a route requires (e.g.
	// admin-only runner enrollment/revocation). Distinct from
	// ClassNotFound: the resource's existence and org membership are
	// already established by the time this fires, so there is no oracle
	// to protect by disguising it as a 404. Naming mirrors the pre-existing,
	// separate internal/audit.ErrClassPermissionDenied (audit-record outcome
	// classification, not an HTTP response class).
	ClassPermissionDenied Class = "permission_denied"
	// ClassRateLimited is returned when a request is refused because the
	// host policy's hourly limit for it is used up. Retrying later can succeed;
	// it is not a permission problem.
	ClassRateLimited Class = "rate_limited"
	// ClassPayloadTooLarge is returned when a request body exceeds the
	// ceiling of the route that reads it; the body is never echoed.
	ClassPayloadTooLarge Class = "payload_too_large"
	// ClassMetadataNotApproved is returned when a carrier's host and target
	// are not a destination the organization's deployment policy admits for
	// this secret. The answer never names the host or the path.
	ClassMetadataNotApproved Class = "metadata_not_approved"
	// ClassDeploymentNotConfirmed is returned when no completed deployment of
	// the requested version to the requested destination is on record: a
	// carrier is registered only with proof that the value was laid there.
	ClassDeploymentNotConfirmed Class = "deployment_not_confirmed"
	// ClassRevokePending is returned when a key rotation run ends with the
	// new version everywhere but the old key still alive: the revoke is
	// pending and is retried with the same run id.
	ClassRevokePending Class = "revoke_pending"
)

// Classes is the closed set of every Class this package defines. A client
// printing a class it received over the wire checks it against this set
// instead of echoing whatever string the peer sent.
func Classes() []Class {
	return []Class{
		ClassInternal, ClassInvalidArgument, ClassNotReady, ClassUnauthenticated,
		ClassNotFound, ClassSecretNotFound, ClassOverrideLocked, ClassNoStoreBound,
		ClassAmbiguousContext, ClassAlreadyExists, ClassPermissionDenied, ClassRateLimited, ClassPayloadTooLarge,
		ClassMetadataNotApproved, ClassDeploymentNotConfirmed, ClassRevokePending,
	}
}

// Error is an application error with a stable class and a template
// message. It implements the standard error interface.
type Error struct {
	Class   Class
	Message string
}

func (e *Error) Error() string { return e.Message }

// New builds an *Error.
func New(class Class, message string) *Error {
	return &Error{Class: class, Message: message}
}

// Body is the exact JSON shape an error takes on the wire — the closed
// field list from the threat model's §4.3, nothing more.
type Body struct {
	ErrorClass string `json:"error_class"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
}
