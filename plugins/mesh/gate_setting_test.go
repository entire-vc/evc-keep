package mesh_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/deployment"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	kstore "github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// gateDB is a migrated scratch database with one organisation.
func gateDB(t *testing.T) (*pgxpool.Pool, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	dsn := pgscratch.New(t, nil)
	mdb, err := kstore.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	mp, err := kstore.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err = mp.Up(ctx); err != nil {
		t.Fatal("migrate test database")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test pool")
	}
	t.Cleanup(pool.Close)
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES ($1,'gate-setting')`, org); err != nil {
		t.Fatal("insert organization")
	}
	return pool, org
}

// gateRequest uses the enrolled runner registry and the real catalog. No
// matching deployment policy means Submit requires an ordinary approval.
func gateRequest(t *testing.T, pool *pgxpool.Pool, org uuid.UUID) deployment.Request {
	t.Helper()
	user, store, secret, version, runner := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate runner key")
	}
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,org_id,email) VALUES($1,$2,'test@example.invalid')`, []any{user, org}},
		{`INSERT INTO stores(id,org_id,provider,name,owner_scope_level,owner_scope_id) VALUES($1,$2,'builtin','test','org',$2)`, []any{store, org}},
		{`INSERT INTO secrets(id,org_id,scope_level,scope_id,name,class,type,store_id,provider_ref) VALUES($1,$2,'org',$2,'DB_PASSWORD','prod','generic',$3,'builtin://test')`, []any{secret, org, store}},
		{`INSERT INTO secret_versions(id,org_id,secret_id,provider_version,fingerprint,length) VALUES($1,$2,$3,'v1','kfp1:k1:abcdefghijklmnop',12)`, []any{version, org, secret}},
		{`INSERT INTO runners(id,org_id,host,cert_serial,cert_not_after,hpke_public_key,uid_shared,host_labels,attrs_source) VALUES($1,$2,'test-host','serial',$3,$4,false,'{}','enroll_token')`, []any{runner, org, time.Now().Add(time.Hour), key.PublicKey().Bytes()}},
	} {
		if _, err := pool.Exec(context.Background(), stmt.sql, stmt.args...); err != nil {
			t.Fatal("insert approval request fixture")
		}
	}
	return deployment.Request{OrgID: org, Scope: tenancy.Org(org), SecretID: secret, VersionID: version, RunnerID: runner,
		RequestID: uuid.NewString(), Target: runnerproto.Target{Kind: runnerproto.TargetFile, Path: "/srv/app/key", Mode: 0o600, UID: 1001, GID: 1001},
		Actor: audit.Actor{Type: audit.ActorUser, ID: user.String(), Via: audit.ViaAPI}}
}

// The workspace setting approvals_via_mesh decides whether a request that
// needs approval opens a Mesh card. mock: external boundary — Mesh's HTTP API; the
// real card client, the gate service over PostgreSQL and the confirmer the
// deploy and rotation approvals call. false: no POST
// /api/v1/projects/{id}/tasks, and the approval commits as an ordinary Keep
// approval; true, and a Mesh that never sent the setting: exactly one.
func TestApprovalsViaMeshSettingDecidesTheCard(t *testing.T) {
	no, yes := false, true
	for _, tc := range []struct {
		name    string
		setting *bool
		posts   int
	}{
		{"false", &no, 0},
		{"true", &yes, 1},
		{"never sent", nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pool, org := gateDB(t)
			if _, err := pool.Exec(ctx, `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by,approvals_via_mesh) VALUES($1,$2,'https://mesh.example.invalid',$3,$4)`,
				uuid.New(), org, uuid.New(), tc.setting); err != nil {
				t.Fatal(err)
			}
			s := newGateStub(t)
			var buf bytes.Buffer
			g, project, _ := newGates(t, s, &buf)
			repo := deployment.NewRepo(pool, audit.NewJournal(pool))
			repo.WithConfirmer(deployment.GateConfirmer{Svc: meshgate.New(meshgate.NewPG(pool), deployment.GateApprovals{Src: repo}, g, nil)})
			result, err := repo.Submit(ctx, gateRequest(t, pool, org))
			if err != nil || result.Status != deployment.NeedsApproval || result.ApprovalID == uuid.Nil {
				t.Fatalf("Submit status %s, %v: want a pending Keep approval", result.Status, err)
			}
			pending, err := repo.ListApprovals(ctx, org, 10)
			if err != nil || len(pending) != 1 || pending[0].ID != result.ApprovalID || pending[0].Status != "requested" {
				t.Fatal("the committed approval is absent from Keep's approval list")
			}

			want := "POST /api/v1/projects/" + project + "/tasks"
			posts := 0
			for _, c := range s.seen() {
				if c == want {
					posts++
				}
			}
			if posts != tc.posts {
				t.Fatalf("%s sent %d times, want %d (calls %v)", want, posts, tc.posts, s.seen())
			}
			if tc.posts == 0 && len(s.seen()) != 0 {
				t.Fatalf("Mesh was called with the setting off: %v", s.seen())
			}
			var gates int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM mesh_gate_requests WHERE org_id=$1`, org).Scan(&gates); err != nil || gates != tc.posts {
				t.Fatalf("gate rows = %d, %v; want %d", gates, err, tc.posts)
			}
		})
	}
}
