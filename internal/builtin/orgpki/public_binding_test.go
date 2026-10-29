package orgpki

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"github.com/google/uuid"
	"testing"
)

func TestLookupAuthenticatesPublicMaterial(t *testing.T) {
	for _, column := range []string{"ca_cert_der", "sign_pub_key", "sign_key_id"} {
		t.Run(column, func(t *testing.T) {
			repo, db := newRepo(t)
			org := seedOrg(t, db)
			ctx := context.Background()
			original, err := repo.Ensure(ctx, org)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok, err := repo.Lookup(ctx, org); err != nil || !ok {
				t.Fatal("unaltered public material control failed")
			}
			var replacement any
			switch column {
			case "ca_cert_der":
				other := seedOrg(t, db)
				b, e := repo.Ensure(ctx, other)
				if e != nil {
					t.Fatal(e)
				}
				replacement = b.CACertDER
			case "sign_pub_key":
				b := append([]byte(nil), original.SignPubKey...)
				b[0] ^= 1
				replacement = b
			case "sign_key_id":
				replacement = original.SignKeyID + "-swapped"
			}
			if _, err := db.Exec(ctx, "UPDATE org_ca SET "+column+"=$1 WHERE org_id=$2", replacement, org); err != nil {
				t.Fatal(err)
			}
			if _, ok, err := repo.Lookup(ctx, org); err == nil || ok {
				t.Fatal("Lookup trusted substituted public material")
			}
		})
	}
}
func TestExistingCARejectsDifferentRoot(t *testing.T) {
	for _, changeID := range []bool{true, false} {
		t.Run(map[bool]string{true: "id", false: "key"}[changeID], func(t *testing.T) {
			db := testDB(t)
			org := seedOrg(t, db)
			ctx := context.Background()
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			original := append([]byte(nil), key...)
			defer wipe(original)
			repo, err := NewRepoFromKey(db, "root-one", key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Ensure(ctx, org); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewRepoFromKey(db, "root-one", append([]byte(nil), original...))
			if err != nil {
				t.Fatal(err)
			}
			csr, _ := runnerCSR(t, pkix.Name{})
			if _, err := restarted.IssueRunnerCert(ctx, org, uuid.New(), "h", csr); err != nil {
				t.Fatal("stable root restart control failed")
			}
			id := "root-one"
			if changeID {
				id = "root-two"
			} else {
				original[0] ^= 1
			}
			wrong, err := NewRepoFromKey(db, id, append([]byte(nil), original...))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrong.Ensure(ctx, org); err == nil {
				t.Fatal("Ensure accepted CA encrypted under another root")
			}
		})
	}
}
