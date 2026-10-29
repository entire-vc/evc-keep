// Package provider defines the storage-provider contract of Keep.
//
// A provider is where secret values live: the built-in store, 1Password,
// SOPS/age, Vault/OpenBao and so on. Providers run inside the runner (see
// ADR-001 §3.3); the server never calls an external provider.
//
// Rules every implementation must follow (enforced by package providertest):
//
//   - A value never appears in an error, a log record or in Meta.
//   - Errors are classified: errors.Is(err, ErrX) holds for exactly the class
//     that describes the failure.
//   - Write creates a new version and never disables the previous one; the
//     second phase of a rotation is an explicit Disable.
//   - Read-only calls (Resolve, Version) are idempotent.
//
// The interface uses only serialisable types, so it can be moved behind an
// out-of-process gRPC boundary without changing signatures.
package provider

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Ref locates a secret inside a provider.
type Ref struct {
	// Path is the provider-specific locator, e.g. "op://vault/item/field"
	// or "builtin://<secret-id>". It is metadata, never a value.
	Path string
	// Version selects a specific version. Empty means the current one.
	Version string
}

// refPattern is the closed set of locator schemes Keep knows how to route to
// a provider, each followed by a non-empty provider-specific tail: the
// built-in store, 1Password, SOPS/age, and Vault/OpenBao (README, ADR-001
// §3). A caller-supplied provider_ref must match this shape rather than be
// accepted as an arbitrary string — an API surface that stores whatever
// string a caller sends here would let a caller point Keep's runner at a
// locator it never validated (threat model §4.3).
var refPattern = regexp.MustCompile(`^(builtin|op|sops|vault)://\S+$`)

// reservedRefPrefix is where Keep seals its own service credential (the Mesh
// service token, with its staged and dropped companions) in the organisation's
// built-in store. That store is the one tenant refs point at, so a caller's
// provider_ref must never name it: through such a ref the token could be
// delivered to a runner or overwritten (threat model §4.1, §4.6).
const reservedRefPrefix = "builtin://mesh-service-token"

// ReservedRefPrefix is reservedRefPrefix for the startup check in
// internal/store, which counts catalog rows already under it; one constant
// serves both so the two can never name different things.
const ReservedRefPrefix = reservedRefPrefix

// ValidRef reports whether s has the shape of a provider locator this
// package's implementations understand — never whether the thing it names
// actually exists, which only a provider's own Version/Resolve call can
// answer. A locator under Keep's own credential name is not valid.
func ValidRef(s string) bool {
	return refPattern.MatchString(s) && !strings.HasPrefix(s, reservedRefPrefix)
}

// Meta describes a version without revealing it.
type Meta struct {
	Version   string
	CreatedAt time.Time
	Length    int
	Disabled  bool
}

// Capabilities declares what a provider can do; the conformance suite and
// the orchestrator adapt to it instead of assuming.
type Capabilities struct {
	// Versioning: every Write yields a new, separately addressable version
	// and older versions stay resolvable until disabled.
	Versioning bool
	// Write: Keep may create versions (false for read-only mounts).
	Write bool
	// Disable: a specific version can be disabled (second rotation phase).
	Disable bool
	// AuditLink: the provider keeps its own read log that Keep can
	// correlate with its request_id (R-AUD-2).
	AuditLink bool
}

// Provider is the storage contract.
type Provider interface {
	Capabilities() Capabilities

	// Resolve returns the value and metadata of ref.
	Resolve(ctx context.Context, ref Ref) (secret.Value, Meta, error)

	// Write stores v as a new version of ref.Path and returns its metadata.
	// ref.Version must be empty.
	Write(ctx context.Context, ref Ref, v secret.Value) (Meta, error)

	// Version returns metadata of ref without reading the value where the
	// backend allows it.
	Version(ctx context.Context, ref Ref) (Meta, error)

	// Disable makes a specific version unresolvable. Disabling an already
	// disabled version succeeds. Disabling the only enabled version fails
	// with ErrLastVersion: the orchestrator must never leave a secret with
	// nothing to resolve.
	Disable(ctx context.Context, ref Ref) error
}

// Error classes. Implementations wrap them; callers use errors.Is.
var (
	ErrNotFound    = errors.New("provider: not found")
	ErrDisabled    = errors.New("provider: version disabled")
	ErrUnavailable = errors.New("provider: backend unavailable")
	ErrUnsupported = errors.New("provider: operation not supported")
	ErrInvalidRef  = errors.New("provider: invalid reference")
	ErrLastVersion = errors.New("provider: refusing to disable the last enabled version")
	ErrDenied      = errors.New("provider: access denied")
)

// Classes lists every error class, in the order Class reports them.
var Classes = []error{
	ErrNotFound, ErrDisabled, ErrUnavailable, ErrUnsupported,
	ErrInvalidRef, ErrLastVersion, ErrDenied,
}

// Class returns the first class err belongs to, or nil if none.
func Class(err error) error {
	for _, c := range Classes {
		if errors.Is(err, c) {
			return c
		}
	}
	return nil
}
