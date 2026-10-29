// Package rotation is the contract of a provider that can issue and revoke a
// credential on its own side (an agent key, a token): the thing a two-phase
// rotation drives. It carries metadata and secret.Value only and imports
// nothing of any platform that implements it.
//
// Rules every implementation follows:
//
//   - A value appears only in Issued.Value, as a secret.Value. It never
//     appears in an error, a key id or a Status.
//   - A key id is a canonical lowercase UUID: a public name for the key.
//   - Revoke is idempotent per key id. Issue is called once per RunID: the
//     caller records the run's key and never asks again, because a
//     forward-only provider ends the key a repeated Issue would replace.
//   - Errors are classes (errors.Is); their text is never forwarded.
package rotation

import (
	"context"
	"errors"

	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// Capabilities declares how a provider rotates.
type Capabilities struct {
	// DualKey: the old key stays valid after Issue until Revoke, so a failed
	// rotation rolls back by revoking the new key. False means forward-only:
	// issuing a key ends the old one at once and there is no way back.
	DualKey bool
}

// IssueRequest names what the key is for. Both fields are metadata.
type IssueRequest struct {
	// Subject is the provider-side name the key is issued for.
	Subject string
	// RunID is the idempotency key of the rotation run.
	RunID uuid.UUID
}

// Issued is a fresh key: its public id and its value.
type Issued struct {
	KeyID string
	Value secret.Value
}

// Status is what Check says about a key.
type Status struct {
	Active bool
}

// Error classes. Implementations wrap them; callers use errors.Is.
var (
	ErrNotFound    = errors.New("rotation provider: key not found")
	ErrUnavailable = errors.New("rotation provider: backend unavailable")
	ErrDenied      = errors.New("rotation provider: access denied")
)

// RotationProvider issues and revokes keys.
type RotationProvider interface {
	// Kind names the provider type, e.g. "mesh-agent-key".
	Kind() string
	// Issue creates a key. With DualKey=false it also ends the previous key.
	Issue(ctx context.Context, req IssueRequest) (Issued, error)
	// Check reports whether a key is still active.
	Check(ctx context.Context, keyID string) (Status, error)
	// Current names the key that is valid for subject right now, if the provider
	// knows one. It returns the id only. ok=false: the provider does not know,
	// or more than one key is active so none is "the" key; an error is treated
	// the same way by the caller: what is not known is not revoked.
	Current(ctx context.Context, subject string) (keyID string, ok bool, err error)
	// Revoke ends a key. Revoking an ended or unknown key succeeds.
	Revoke(ctx context.Context, keyID string) error
	Capabilities() Capabilities
}

// ValidKeyID reports whether s is a canonical lowercase UUID.
func ValidKeyID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}
