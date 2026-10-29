package meshext

import (
	"context"
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/meshfake"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fedFixture is a migrated database with one organization that installed
// Keep in a workspace of a fake Mesh.
type fedFixture struct {
	ctx  context.Context
	pool *pgxpool.Pool
	mesh *meshfake.Mesh
	fed  *Federation
	org  uuid.UUID
	ws   uuid.UUID
}

func newFedFixture(t *testing.T) *fedFixture {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	ctx := context.Background()
	mdb, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err = provider.Up(ctx); err != nil {
		t.Fatal("migrate test database")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test pool")
	}
	t.Cleanup(pool.Close)
	m, ver, ws := fixture(t)
	f := &fedFixture{ctx: ctx, pool: pool, mesh: m, org: uuid.New(), ws: ws}
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,'fed')`, f.org); err != nil {
		t.Fatal("insert organization")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES($1,$2,$3,$4)`, ws, f.org, m.URL(), uuid.New()); err != nil {
		t.Fatal("insert installation")
	}
	repo := NewRepo(pool)
	f.fed = NewFederation(pool, repo, identity.NewRepo(pool), ver)
	return f
}

func (f *fedFixture) signIn(sub string) error {
	_, _, err := f.fed.SignIn(f.ctx, NewContextToken(sign(f.mesh.Key0(0), nil, f.mesh.Valid(f.ws.String(), sub, sub+"@example.test"))))
	return err
}

func (f *fedFixture) links(t *testing.T, meshUser string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM mesh_user_links WHERE workspace_id=$1 AND mesh_user_id::text=$2`, f.ws, meshUser).Scan(&n); err != nil {
		t.Fatal("count links")
	}
	return n
}

// The first sign-in through Mesh links the Mesh user to the Keep user it
// creates, so a gate card that person answers names them; a second sign-in
// keeps the one link.
func TestSignInLinksTheMeshUser(t *testing.T) {
	f := newFedFixture(t)
	sub := uuid.NewString()
	if err := f.signIn(sub); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	if n := f.links(t, sub); n != 1 {
		t.Fatalf("links after first sign-in = %d, want 1", n)
	}
	var linked uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT l.user_id FROM mesh_user_links l JOIN users u ON u.id=l.user_id AND u.org_id=l.org_id
	 WHERE l.workspace_id=$1 AND l.mesh_user_id=$2 AND l.org_id=$3 AND u.external_ref=$4`, f.ws, sub, f.org, ExternalRef(f.mesh.URL(), sub)).Scan(&linked); err != nil {
		t.Fatal("the link does not name the user the sign-in created")
	}
	if err := f.signIn(sub); err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if n := f.links(t, sub); n != 1 {
		t.Fatalf("links after second sign-in = %d, want 1", n)
	}
}

// A subject that is not a Mesh user id is refused and links nothing.
func TestSignInRefusesASubjectThatIsNotAnID(t *testing.T) {
	f := newFedFixture(t)
	if err := f.signIn("u-1"); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("sign-in with subject u-1: %v, want ErrInvalidContext", err)
	}
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM mesh_user_links) + (SELECT count(*) FROM users)`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused sign-in left %d rows (%v)", n, err)
	}
}

// A link that cannot be written does not open a session.
func TestSignInFailsClosedWhenTheLinkIsNotWritten(t *testing.T) {
	f := newFedFixture(t)
	if _, err := f.pool.Exec(f.ctx, `CREATE FUNCTION refuse_link() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'no'; END $$;
	 CREATE TRIGGER refuse_link BEFORE INSERT ON mesh_user_links FOR EACH ROW EXECUTE FUNCTION refuse_link()`); err != nil {
		t.Fatal("install trigger")
	}
	err := f.signIn(uuid.NewString())
	if err == nil {
		t.Fatal("sign-in opened a session without the link")
	}
	if err.Error() != "meshext: link mesh user: database error" {
		t.Fatalf("sign-in error = %q, want the fixed text", err.Error())
	}
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM tokens`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tokens issued = %d (%v), want 0", n, err)
	}
}
