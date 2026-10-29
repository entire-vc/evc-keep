package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/builtin/orgpki"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootKeyFileRequired(t *testing.T) {
	local, err := builtin.OpenLocalFile(nil, "", "persistent-test", nil, nopAudit)
	if err == nil || local != nil {
		t.Fatal("startup accepted an implicit ephemeral root key")
	}
	local, err = builtin.OpenLocalFile(nil, serverRootKeyFile(t), "persistent-test", nil, nopAudit)
	if err != nil || local == nil {
		t.Fatal("persistent root key positive control failed")
	}

}

func serverRootKeyFile(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("root fixture generation failed")
	}
	defer clear(key)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
	base64.StdEncoding.Encode(encoded, key)
	defer clear(encoded)
	path := filepath.Join(t.TempDir(), "root-key")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal("root fixture write failed")
	}
	return path
}

func TestServeValidatesPersistentRoot(t *testing.T) {
	bin := buildKeepServer(t)
	dsn := pgscratch.New(t, requiredLogSettingsLiteral)
	migrate(t, bin, dsn)
	roleDSN := pgscratch.NewRole(t, dsn, "keep_app")
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open scratch database")
	}
	defer db.Close()
	org := uuid.New()
	if _, err := db.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,'restart-root-test')`, org); err != nil {
		t.Fatal("seed org")
	}
	file := serverRootKeyFile(t)
	id := "persistent-test"
	encoded, err := os.ReadFile(file) // #nosec G304 -- synthetic fixture created in this test's temporary directory
	if err != nil {
		t.Fatal("read synthetic root fixture")
	}
	defer clear(encoded)
	key, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatal("decode synthetic root fixture")
	}
	defer clear(key)
	probe := canary.Of(string(key))
	encodedProbe := canary.Of(string(encoded))
	if !probe.In(string(key)) || !encodedProbe.In(string(encoded)) {
		t.Fatal("root canary positive control failed")
	}
	local, err := builtin.OpenLocalFile(db, file, id, nil, nopAudit)
	if err != nil {
		t.Fatal("load synthetic root")
	}
	repo := orgpki.NewRepoFromLocal(db, local)
	if _, err := repo.Ensure(ctx, org); err != nil {
		t.Fatal("seed persisted CA")
	}
	for _, tc := range []struct {
		name, file, id string
		running        bool
	}{{"stable", file, id, true}, {"missing", "", id, false}, {"wrong-id", file, "other-root", false}, {"wrong-key", serverRootKeyFile(t), id, false}} {
		t.Run(tc.name, func(t *testing.T) {
			out, running, code := runServeWithRoot(t, bin, roleDSN, 2*time.Second, tc.file, tc.id)
			if probe.In(out) || encodedProbe.In(out) {
				t.Error("root material leaked into server output")
			}
			if running != tc.running {
				t.Fatalf("startup running=%v, want %v", running, tc.running)
			}
			if !tc.running && (code != 1 || strings.Contains(out, "listening")) {
				t.Fatal("server opened listener or returned wrong refusal status")
			}
		})
	}
}
