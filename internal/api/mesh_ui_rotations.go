package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RunSummary is one rotation run as the Mesh screen lists it: metadata only.
type RunSummary struct {
	ID             uuid.UUID
	State          string
	ErrorClass     string
	OldVersion     string
	NewVersion     string
	IncidentOpened bool
	StartedBy      string // principal name; empty when the run does not record it
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// MeshUIRotations is what the Mesh screen reads about rotation runs.
// A nil MeshUIRotations hides every rotation block.
type MeshUIRotations interface {
	// Latest returns the newest run of each listed secret that has one.
	Latest(ctx context.Context, org uuid.UUID, secrets []uuid.UUID) (map[uuid.UUID]RunSummary, error)
	// List returns runs of one secret, newest first, and their total.
	List(ctx context.Context, org, secret uuid.UUID, limit, offset int) ([]RunSummary, int, error)
}
