package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInputStoreScopeMapping(t *testing.T) {
	dsn := os.Getenv("KEEP_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEEP_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("pool")
	}
	defer pool.Close()
	path := filepath.Join(t.TempDir(), "root.key")
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	local, err := builtin.OpenLocal(pool, path, obs.New(&logs), nopAudit)
	if err != nil {
		t.Fatal("shared local root")
	}
	svc, err := newInputService(pool, local, "https://keep.example.invalid", obs.New(&logs))
	if err != nil {
		t.Fatal("input service")
	}
	rp, cat := tenancy.New(pool), catalog.New(pool)
	org, err := rp.CreateOrganization(ctx, t.Name(), "")
	if err != nil {
		t.Fatal("organization")
	}
	other, err := rp.CreateOrganization(ctx, t.Name()+"-other", "")
	if err != nil {
		t.Fatal("other organization")
	}
	type mapping struct {
		org                      uuid.UUID
		scope                    tenancy.Scope
		workspace, project, user string
	}
	cases := []mapping{{org: org.ID, scope: tenancy.Org(org.ID)}, {org: other.ID, scope: tenancy.Org(other.ID)}}
	for _, orgID := range []uuid.UUID{org.ID, other.ID} {
		ws, err := rp.CreateWorkspace(ctx, orgID, "workspace")
		if err != nil {
			t.Fatal("workspace")
		}
		project, err := rp.CreateProject(ctx, orgID, ws.ID, "project")
		if err != nil {
			t.Fatal("project")
		}
		user, err := rp.CreateUser(ctx, orgID, "input@example.test")
		if err != nil {
			t.Fatal("user")
		}
		cases = append(cases,
			mapping{org: orgID, scope: tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}, workspace: ws.ID.String()},
			mapping{org: orgID, scope: tenancy.Scope{Level: tenancy.LevelProject, ID: project.ID}, workspace: ws.ID.String(), project: project.ID.String()},
			mapping{org: orgID, scope: tenancy.Scope{Level: tenancy.LevelUser, ID: user.ID}, user: user.ID.String()})
	}
	actor := audit.Actor{Type: audit.ActorUser, ID: uuid.NewString(), Via: audit.ViaAPI}
	var publicKeys [][]byte
	for i, tc := range cases {
		t.Run(string(tc.scope.Level)+"-"+tc.org.String(), func(t *testing.T) {
			name := "input-" + string(tc.scope.Level)
			st, err := cat.CreateStore(ctx, tc.org, "builtin", name, tc.scope)
			if err != nil {
				t.Fatal("store")
			}
			if _, err := cat.CreateStoreBinding(ctx, tc.org, tc.scope, st.ID); err != nil {
				t.Fatal("binding")
			}
			ref, err := cat.CreateRef(ctx, catalog.CreateRefInput{Org: tc.org, Scope: tc.scope, Name: "sample", Class: "dev", Type: "generic", ProviderRef: "builtin://" + name + "/sample"})
			if err != nil {
				t.Fatal("reference")
			}
			link, err := svc.Issue(ctx, ref, st, actor, 0)
			if err != nil {
				t.Fatal("owner scope could not issue link")
			}
			u, err := url.Parse(link.URL)
			if err != nil {
				t.Fatal("link URL")
			}
			token := strings.TrimPrefix(u.Path, "/input/")
			view, err := svc.Read(ctx, token)
			if err != nil {
				t.Fatal("read link")
			}
			var n int
			if pool.QueryRow(ctx, `SELECT count(*) FROM keep_envelope WHERE store_org=$1 AND store_workspace=$2 AND store_project=$3 AND store_user=$4 AND secret_id='__keep_intake_key__'`, tc.org.String(), tc.workspace, tc.project, tc.user).Scan(&n) != nil || n != 1 {
				t.Fatal("store mapped to wrong owner scope")
			}
			for _, public := range publicKeys {
				if bytes.Equal(public, view.PublicKey) {
					t.Fatal("distinct owner scopes shared intake key")
				}
				env := scopeCiphertext(t, public, link.RequestID)
				if _, err := svc.Complete(ctx, token, env); !errors.Is(err, intake.ErrRejected) {
					t.Fatal("foreign store ciphertext accepted")
				}
			}
			publicKeys = append(publicKeys, view.PublicKey)
			if i == 0 {
				bad := st
				bad.OwnerScope.ID = other.ID
				if _, err := svc.Issue(ctx, ref, bad, actor, 0); !errors.Is(err, intake.ErrUnavailable) {
					t.Fatal("foreign organization owner accepted")
				}
			}
			if tc.scope.Level == tenancy.LevelProject && tc.org == org.ID {
				for _, foreign := range cases {
					if foreign.org == other.ID && foreign.scope.Level == tenancy.LevelProject {
						bad := st
						bad.OwnerScope = foreign.scope
						if _, err := svc.Issue(ctx, ref, bad, actor, 0); !errors.Is(err, intake.ErrUnavailable) {
							t.Fatal("foreign project owner accepted")
						}
					}
				}
			}
			if _, err := svc.Complete(ctx, token, scopeCiphertext(t, view.PublicKey, link.RequestID)); err != nil {
				t.Fatal("owner scope could not complete input")
			}
			if pool.QueryRow(ctx, `SELECT count(*) FROM keep_envelope WHERE store_org=$1 AND store_workspace=$2 AND store_project=$3 AND store_user=$4 AND secret_id=$5`, tc.org.String(), tc.workspace, tc.project, tc.user, ref.ProviderRef).Scan(&n) != nil || n != 1 {
				t.Fatal("input written at wrong owner scope")
			}
		})
	}
}

func scopeCiphertext(t *testing.T, public []byte, request string) intake.Envelope {
	t.Helper()
	pk, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(public)
	if err != nil {
		t.Fatal("public key")
	}
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	sender, err := suite.NewSender(pk, []byte("keep/intake/v1\x00"+request))
	if err != nil {
		t.Fatal("sender")
	}
	enc, seal, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal("setup")
	}
	ct, err := seal.Seal([]byte("synthetic input"), nil)
	if err != nil {
		t.Fatal("seal")
	}
	return intake.Envelope{Enc: enc, Ciphertext: ct}
}
