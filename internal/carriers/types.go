// Package carriers keeps a tenant-scoped registry of approved deployment
// destinations. It never imports or holds secret values.
package carriers

import (
	"context"
	"errors"
	"time"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

var (
	ErrNotFound    = errors.New("carriers: secret not found")
	ErrMetadata    = errors.New("carriers: metadata not approved")
	ErrFingerprint = errors.New("carriers: fingerprint rejected")
	ErrDeployment  = errors.New("carriers: deployment not confirmed")
	ErrInternal    = errors.New("carriers: database operation failed")
)

type State string

const (
	Registered State = "registered"
	Stale      State = "stale"
	Unknown    State = "unknown"
)

// Metadata identifies an approved destination. TargetField distinguishes
// two secret slots within the same file. HealthcheckRef is an approved
// check identifier, never a command, URL with credentials, or check output.
type Metadata struct {
	Host           string
	TargetKind     runnerproto.TargetKind
	TargetPath     string
	TargetField    string
	Consumer       string
	HealthcheckRef string
}

// MetadataPolicy must compare the complete descriptor with a destination
// approved for this org and secret (for example, a server-held deployment
// plan). Merely accepting syntactically valid strings is not sufficient:
// an injected value can look exactly like a valid path or consumer name.
// Policies must not log inputs and must honor the supplied context. Callers
// must supply a bounded context deadline: approval runs while the catalog
// secret and version locks are held. Cancellation must stop policy work;
// an unbounded or context-ignoring policy can block catalog operations.
type MetadataPolicy interface {
	Approved(context.Context, uuid.UUID, uuid.UUID, Metadata) (bool, error)
}

// Registration is trusted control-plane metadata, never a request body.
// Org is deliberately absent: it is a separate authenticated argument.
type Registration struct {
	SecretID uuid.UUID
	Version  string
	Metadata
	LastFP string
}

// Carrier is an internal persistence record, not an API response DTO.
// Public adapters must select the closed response fields explicitly.
type Carrier struct {
	ID       uuid.UUID
	OrgID    uuid.UUID
	SecretID uuid.UUID
	Version  string
	Metadata
	LastFP string
	// RunnerID is the runner that laid this version at this destination,
	// read from the deployment record when the carrier is served; it is not
	// stored. Nil when no such record is left.
	RunnerID       uuid.UUID
	State          State
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastVerifiedAt *time.Time
}

// DeploymentHook is invoked by the orchestrator only after an authenticated
// runner result has passed the signed job/version/fingerprint checks.
// Binding it into the orchestrator is intentionally separate from storage.
type DeploymentHook interface {
	OnDeployed(context.Context, uuid.UUID, Registration, runnerproto.Result) error
}
