package identity

import "github.com/google/uuid"

// newID returns a fresh UUIDv7 — Keep's entity id format (see
// internal/reqid's doc for why: sortable by creation time without a
// sequential counter). Every row this package inserts gets its id from
// here, in Go, never from a database DEFAULT — gen_random_uuid() (the only
// UUID generator pgcrypto provides) is UUIDv4.
func newID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.UUID{}, err
	}
	return id, nil
}
