package tenancy

import (
	"time"

	"github.com/google/uuid"
)

// SecretRef is a secrets row: metadata only, never a value. This is the
// type [Repo.Resolve] and internal/catalog's create-ref/list/meta all
// return — internal/catalog imports this package for it, so the schema's
// notion of "a secret" has exactly one Go shape.
type SecretRef struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Scope       Scope
	Name        string
	Class       string
	Type        string
	StoreID     uuid.UUID
	ProviderRef string
	Description *string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
