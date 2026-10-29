package builtin

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// testPool opens a pool against a real PostgreSQL instance — see
// CONTRIBUTING.md: the database layer is never mocked. CI provides one via
// the "postgres" service (.gitlab-ci.yml); locally, point
// KEEP_DATABASE_URL at a migrated throwaway instance (skill keep-local-ci).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testPoolSized(t, 0)
}

// testPoolSized is testPool with an explicit MaxConns (0 keeps pgxpool's own
// default). A small pool is what makes a per-call connection budget
// regression — a call that starts needing more simultaneous connections
// than before — observable in a short-running test: see
// TestWrite_DoesNotExhaustPool.
func testPoolSized(t *testing.T, maxConns int32) *pgxpool.Pool {
	t.Helper()
	return testPoolParams(t, maxConns, nil)
}

// testPoolParams is testPoolSized plus server run-time parameters set on every
// connection of the pool (e.g. default_transaction_isolation), for tests of a
// deployment setting the code must not depend on.
func testPoolParams(t *testing.T, maxConns int32, params map[string]string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	for k, v := range params {
		cfg.ConnConfig.RuntimeParams[k] = v
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// recAudit is a recording sealer.Auditor, the same shape as the sealer
// package's own test fixture.
type recAudit struct{ events []sealer.Event }

func (a *recAudit) Record(e sealer.Event) { a.events = append(a.events, e) }

// testSealer returns a Sealer persisting its KEK records to pool, with a
// fresh random root key — every test gets an independent root, so a leaked
// or reused key in one test cannot mask a bug in another.
func testSealer(t *testing.T, pool *pgxpool.Pool) (*sealer.Sealer, *recAudit) {
	t.Helper()
	s, root, a := testSealerWithRoot(t, pool)
	_ = root
	return s, a
}

// testSealerWithRoot is testSealer plus the sealer.RootKey it built the
// Sealer over — only a couple of tests need the root itself (a real
// database-level attack has to unwrap a KEK the same way the sealer would,
// see TestC6_DatabaseLevelAttack), so this stays a separate helper instead
// of changing testSealer's signature for every existing call site.
func testSealerWithRoot(t *testing.T, pool *pgxpool.Pool) (*sealer.Sealer, sealer.RootKey, *recAudit) {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	root, err := sealer.NewLocalRootKey(randID(t, "root"), k)
	if err != nil {
		t.Fatal(err)
	}
	a := &recAudit{}
	return sealer.New(root, a, newStore(pool)), root, a
}

// randID returns a short random identifier so each test works against its
// own organisation / scope, independent of whatever earlier test runs left
// in a persistent local database.
func randID(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + "-" + hex.EncodeToString(b)
}

func providerRef(path string) provider.Ref { return provider.Ref{Path: path} }

func providerRefVersion(path, version string) provider.Ref {
	return provider.Ref{Path: path, Version: version}
}

func secretOf(s string) secret.Value { return secret.New([]byte(s)) }

// aadForTest independently reimplements internal/builtin/sealer's
// unexported aad() wire format (ADR-001 §5, rootkey.go: a label followed by
// each field length-prefixed as a big-endian uint32) rather than importing
// it, so an attack test built on this does not rely on, or trust, the
// production code's own AAD builder — it is meant to fail the same way an
// outside attacker who only knows the documented format would.
func aadForTest(label string, fields ...string) []byte {
	b := []byte(label)
	for _, f := range fields {
		n := len(f)
		if n > math.MaxUint32 {
			panic("aadForTest: field too long")
		}
		b = binary.BigEndian.AppendUint32(b, uint32(n))
		b = append(b, f...)
	}
	return b
}

// scopeKeyForTest reimplements sealer.Scope's unexported key() method
// (level.go) independently, for the same reason as aadForTest.
func scopeKeyForTest(s sealer.Scope) string {
	lp := func(id string) string { return strconv.Itoa(len(id)) + ":" + id }
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

// kekAADForTest reimplements sealer's unexported kekAAD, for the same
// reason as aadForTest.
func kekAADForTest(id, org, domainKey, rootID string) []byte {
	return aadForTest("keep/kek/v1", org, domainKey, id, rootID)
}

// dekAADForTest reimplements sealer's unexported dekAAD, for the same
// reason as aadForTest.
func dekAADForTest(storeKey, secretID, version, kekID string) []byte {
	return aadForTest("keep/dek/v1", storeKey, secretID, version, kekID)
}

// valueAADForTest reimplements sealer's unexported valueAAD, for the same
// reason as aadForTest.
func valueAADForTest(orgID, secretID, name, version string) []byte {
	return aadForTest("keep/value/v1", orgID, secretID, name, version)
}
