// Package sealer is the only code in the built-in provider that handles key
// material and plaintext values (ADR-001 §5, threat model §2.2).
//
// Key hierarchy:
//
//	root key (KMS / separate key file)
//	  └─ KEK, one per key domain, random, stored wrapped by the root key
//	       └─ DEK, one per secret version, random, stored wrapped by a KEK
//	            └─ value, AES-256-GCM
//
// A key domain is the scope whose KEK protects a store. Which scope that is
// depends on the organisation's key level (tenancy model §5): at the default
// level, LevelUser, every store gets its own KEK, so the built-in secrets of
// two users of one organisation are separated cryptographically and not only
// by access checks. Coarser levels share one KEK among the stores below a
// project, a workspace or the whole organisation.
//
// Changing the level re-wraps DEKs under the KEKs of the new domains; the
// value ciphertexts are never touched. Every envelope records the KEK that
// wraps its DEK, so a change interrupted half-way leaves every envelope
// readable and can simply be run again.
//
// Only internal/builtin may import this package (depguard rule "sealer").
package sealer

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// Level is the granularity at which KEKs are separated.
type Level int

// Levels from the finest to the coarsest. The order is meaningful: a larger
// Level shares a KEK among more stores.
const (
	LevelUser Level = iota + 1
	LevelProject
	LevelWorkspace
	LevelOrg
)

// DefaultLevel is the level of a new organisation (product decision).
const DefaultLevel = LevelUser

// LevelStore persists an organisation's key level so it survives a restart
// and is shared by every server process reading the same database. Before
// this existed, the level lived only in the Sealer's own memory: a restart
// silently reset it to DefaultLevel with no audit trail, and two server
// processes could each act on their own stale view of it, one able to
// create an active KEK under a level the other had already moved the
// organisation away from — letting two processes converge two users onto a
// shared KEK while the level nominally stayed "user".
//
// Persisting the level is not enough on its own: ChangeLevel does not just
// flip that one row, it also re-wraps every existing DEK and retires the
// KEKs the new level no longer uses, and Seal reads the level to pick which
// KEK a brand new DEK gets wrapped under. Lock is what keeps those two
// operations from interleaving — see ChangeLevel's and Seal's doc comments
// for the race a lock held only around the level row's own read/write
// (rather than the whole operation) leaves open.
type LevelStore interface {
	// Level returns org's current key level, or DefaultLevel if none was
	// ever set.
	Level(ctx context.Context, org string) (Level, error)

	// SetLevel persists level as org's current key level, attributing the
	// write to actor. The caller must already hold an exclusive Lock for
	// org — SetLevel does no locking of its own.
	SetLevel(ctx context.Context, org string, level Level, actor string) error

	// Lock acquires org's key-level lock and returns a Store bound to the
	// same connection the lock is held on — so Level/SetLevel and every
	// KEKStore call made through the returned Store (not through the
	// original) cost no additional pool connection beyond the one already
	// held for the lock — plus a function that releases it; the caller must
	// call release exactly once. It blocks until acquired, in this process
	// and every other reading the same database (a real advisory lock, not
	// an in-process mutex).
	//
	// exclusive is for ChangeLevel: it holds the lock for its entire
	// operation — reading the level, deciding, persisting it, re-wrapping
	// every DEK and retiring old KEKs — so no other Lock call for the same
	// org, exclusive or shared, can run at any point during it. ChangeLevel
	// runs its Level/SetLevel reads and writes, and every KEKStore call
	// Rewrap's callback and retire make (activeKEK, Get, ActiveList,
	// Retire), through the returned Store. If the caller's EnvelopeStore
	// implements [LockBound], ChangeLevel rebinds it to the returned Store
	// too, so the whole operation needs no pool connection beyond the one the
	// lock already holds.
	//
	// Non-exclusive (shared) exists for symmetry and is what this
	// interface's own tests exercise directly; Write and FingerprintKey do
	// not call it — holding a lock across their whole operation while also
	// needing their own transaction for the insert would cost them a
	// second connection each, so they instead take
	// pg_advisory_xact_lock_shared on the same key as the first statement
	// inside their own transaction and run every store call through that
	// transaction (store.withTx, Sealer.WithStore) — one connection for
	// the whole call. Either form conflicts correctly with the other:
	// Postgres advisory locks track session-held and transaction-held
	// grants on the same key together regardless of which flavour either
	// side used.
	Lock(ctx context.Context, org string, exclusive bool) (locked Store, release func(context.Context) error, err error)
}

var levelNames = map[Level]string{
	LevelUser:      "user",
	LevelProject:   "project",
	LevelWorkspace: "workspace",
	LevelOrg:       "organization",
}

func (l Level) String() string {
	if n, ok := levelNames[l]; ok {
		return n
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// Valid reports whether l is one of the defined levels.
func (l Level) Valid() bool { _, ok := levelNames[l]; return ok }

// Weakens reports whether moving from l to to shares KEKs among more stores,
// i.e. weakens the isolation between tenants of the organisation.
func (l Level) Weakens(to Level) bool { return to > l }

// ErrInvalidLevel is returned for an unknown level name or value.
var ErrInvalidLevel = errors.New("sealer: invalid key level")

// ParseLevel parses a level name as used in instance and plugin settings.
func ParseLevel(s string) (Level, error) {
	for l, n := range levelNames {
		if n == s {
			return l, nil
		}
	}
	if s == "org" {
		return LevelOrg, nil
	}
	return 0, ErrInvalidLevel
}

// Scope is the owner scope of a store. A user scope sits directly under the
// organisation (tenancy model §1); a project scope needs its workspace.
type Scope struct {
	// PKI separates organization CA/signing KEKs from value KEKs.
	// It is valid only at organization scope and ignores value key levels.
	PKI       bool
	Org       string
	Workspace string
	Project   string
	User      string
}

// ErrInvalidScope is returned for a scope that does not name one level.
var ErrInvalidScope = errors.New("sealer: invalid scope")

func (s Scope) validate() error {
	switch {
	case s.PKI && (s.Workspace != "" || s.Project != "" || s.User != ""):
		return ErrInvalidScope
	case s.Org == "":
		return ErrInvalidScope
	case s.User != "" && (s.Workspace != "" || s.Project != ""):
		return ErrInvalidScope
	case s.Project != "" && s.Workspace == "":
		return ErrInvalidScope
	}
	return nil
}

// key renders the scope as a stable identifier, used for AAD and indexes.
// Every id is written with its byte length in front of it, so no two distinct
// scopes can render alike: with a bare separator, workspace "w/proj/p" and
// workspace "w" + project "p" would share one key, and the AAD that binds a
// wrapped DEK to its store would accept one store's envelope as the other's.
func (s Scope) key() string {
	if s.PKI {
		return "pki:" + lp(s.Org)
	}
	switch {
	case s.User != "":
		return "org:" + lp(s.Org) + "/user:" + lp(s.User)
	case s.Project != "":
		return "org:" + lp(s.Org) + "/ws:" + lp(s.Workspace) + "/proj:" + lp(s.Project)
	case s.Workspace != "":
		return "org:" + lp(s.Org) + "/ws:" + lp(s.Workspace)
	}
	return "org:" + lp(s.Org)
}

// lp length-prefixes one id for [Scope.key].
func lp(id string) string { return strconv.Itoa(len(id)) + ":" + id }

// Domain returns the scope whose KEK protects a store owned by s when the
// organisation's key level is l. A user scope has no workspace or project
// above it, so at any level coarser than LevelUser it falls to the
// organisation.
func Domain(s Scope, l Level) Scope {
	if s.PKI {
		return s
	}
	org := Scope{Org: s.Org}
	switch {
	case s.User != "":
		if l == LevelUser {
			return s
		}
		return org
	case s.Project != "":
		switch {
		case l <= LevelProject:
			return s
		case l == LevelWorkspace:
			return Scope{Org: s.Org, Workspace: s.Workspace}
		}
		return org
	case s.Workspace != "":
		if l <= LevelWorkspace {
			return s
		}
		return org
	}
	return org
}
