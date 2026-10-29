package tenancy

import "github.com/google/uuid"

// Level is a scope's granularity — one of the tokens the tenancy model uses
// literally in its wire notation: org:<id>, ws:<id>, proj:<id>, user:<id>
// (§1). It is a different vocabulary from internal/builtin/sealer.Level
// (key-level granularity, §5.1) — the two are unrelated settings that
// happen to share four English words.
type Level string

const (
	LevelOrg       Level = "org"
	LevelWorkspace Level = "ws"
	LevelProject   Level = "proj"
	LevelUser      Level = "user"
)

// Valid reports whether l is one of the four defined levels.
func (l Level) Valid() bool {
	switch l {
	case LevelOrg, LevelWorkspace, LevelProject, LevelUser:
		return true
	}
	return false
}

// Scope is the (level, id) pair every table in this schema keys a
// polymorphic reference on (§1: a scope is always a (level, id) pair).
type Scope struct {
	Level Level
	ID    uuid.UUID
}

// Org is the org-level scope for org — the top of every chain.
func Org(org uuid.UUID) Scope { return Scope{Level: LevelOrg, ID: org} }

// String renders s in the "level:id" notation stored in the TEXT scope
// columns of the identity tables (services.owner_scope, memberships.scope).
func (s Scope) String() string { return string(s.Level) + ":" + s.ID.String() }
