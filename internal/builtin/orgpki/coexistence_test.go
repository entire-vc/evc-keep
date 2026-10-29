package orgpki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509/pkix"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

func TestPKIAndBuiltinCoexist(t *testing.T) {
	for _, pkiFirst := range []bool{true, false} {
		name := "value-first"
		if pkiFirst {
			name = "pki-first"
		}
		t.Run(name, func(t *testing.T) {
			db := testDB(t)
			org := seedOrg(t, db)
			ctx := context.Background()
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatal("root generation failed")
			}
			defer clear(key)
			local, err := builtin.NewLocal(db, "local-v1", bytes.Clone(key), nil, func(builtin.KeyEvent) {})
			if err != nil {
				t.Fatal("shared root constructor failed")
			}
			repo := NewRepoFromLocal(db, local)
			p := local.Provider(org.String(), "", "", "")
			c := canary.New()
			v := secret.New([]byte(c.Value(1)))
			defer v.Wipe()
			ensure := func() {
				if _, err := repo.Ensure(ctx, org); err != nil {
					t.Fatal("PKI and builtin cannot coexist: CA unavailable")
				}
			}
			write := func() {
				if _, err := p.Write(ctx, provider.Ref{Path: "coexist"}, v); err != nil {
					t.Fatal("PKI and builtin cannot coexist: value unavailable")
				}
			}
			if pkiFirst {
				ensure()
				write()
			} else {
				write()
				ensure()
			}
			var roots, domains int
			if err := db.QueryRow(ctx, `SELECT count(DISTINCT root_key_id),count(DISTINCT domain_key) FROM keep_kek WHERE org_id=$1`, org.String()).Scan(&roots, &domains); err != nil || roots != 1 || domains != 2 {
				t.Fatal("process root or PKI domain is not shared/isolated")
			}
			restarted, err := builtin.NewLocal(db, "local-v1", bytes.Clone(key), nil, func(builtin.KeyEvent) {})
			if err != nil {
				t.Fatal("restart root failed")
			}
			if _, ok, err := NewRepoFromLocal(db, restarted).Lookup(ctx, org); err != nil || !ok {
				t.Fatal("shared root cannot authenticate PKI after restart")
			}
			opened, _, err := restarted.Provider(org.String(), "", "", "").Resolve(ctx, provider.Ref{Path: "coexist"})
			if err != nil {
				t.Fatal("shared root cannot read value after restart")
			}
			defer opened.Wipe()
			var matches bool
			secret.Expose(opened, func(raw []byte) { matches = c.In(string(raw)) })
			if !matches {
				t.Fatal("value round trip changed")
			}
		})
	}
}

func TestPKISurvivesValueRewrapAndPurge(t *testing.T) {
	db := testDB(t)
	org := seedOrg(t, db)
	ctx := context.Background()
	s := newTestSealer(t, db)
	repo := NewRepo(db, s)
	before, err := repo.Ensure(ctx, org)
	if err != nil {
		t.Fatal("create CA failed")
	}
	admin := builtin.NewAdmin(db, s, org.String(), nil)
	if _, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "test-admin", true); err != nil {
		t.Fatal("set organization key level failed")
	}
	p := builtin.New(db, s, sealer.Scope{Org: org.String(), User: "test-user"}, nil)
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))
	defer v.Wipe()
	if _, err := p.Write(ctx, provider.Ref{Path: "rewrap"}, v); err != nil {
		t.Fatal("write value failed")
	}
	var caKEK, valueKEK string
	if err := db.QueryRow(ctx, `SELECT ca_kek_id FROM org_ca WHERE org_id=$1`, org).Scan(&caKEK); err != nil {
		t.Fatal("read CA key id failed")
	}
	if err := db.QueryRow(ctx, `SELECT kek_id FROM keep_envelope WHERE store_org=$1 AND name='rewrap'`, org).Scan(&valueKEK); err != nil {
		t.Fatal("read value key id failed")
	}
	if caKEK == valueKEK {
		t.Error("PKI and values share a KEK domain")
	}
	if _, err := admin.ChangeLevel(ctx, sealer.LevelUser, "test-admin", false); err != nil {
		t.Fatal("rewrap value failed")
	}
	// The organization KEK can now be retired after its value DEKs moved.
	if err := builtin.NewKeyStore(db).Retire(ctx, org.String(), []string{valueKEK}); err != nil {
		t.Fatal("retire value KEK failed")
	}
	n, err := admin.Purge(ctx, "test-admin")
	if err != nil || n == 0 {
		t.Fatal("value KEK purge did not run")
	}
	after, ok, err := repo.Lookup(ctx, org)
	if err != nil || !ok || !bytes.Equal(before.CACertDER, after.CACertDER) || !bytes.Equal(before.SignPubKey, after.SignPubKey) {
		t.Fatal("value rewrap/purge broke PKI")
	}
	rec, ok, err := repo.loadRecord(ctx, org)
	if err != nil || !ok {
		t.Fatal("PKI record unavailable")
	}
	sign, err := s.Open(ctx, signRef(org, rec.signKeyID, rec.signPubKey), rec.signEnv)
	if err != nil {
		t.Fatal("signing key lost after value purge")
	}
	defer sign.Wipe()
	msg := []byte("public job-signature control")
	var valid bool
	secret.Expose(sign, func(raw []byte) {
		valid = ed25519.Verify(after.SignPubKey, msg, ed25519.Sign(ed25519.PrivateKey(raw), msg))
	})
	if !valid {
		t.Fatal("job signing failed after value purge")
	}
	csr, priv := runnerCSR(t, pkix.Name{})
	defer clear(priv)
	if _, err := repo.IssueRunnerCert(ctx, org, uuid.New(), "host.example", csr); err != nil {
		t.Fatal("CA issuance failed after value purge")
	}
}
