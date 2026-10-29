package catalog

import (
	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"strings"
	"testing"
)

func TestBuiltinStoreUniqueOwnerScope(t *testing.T) {
	f := newFixture(t)
	scope := tenancy.Org(f.org.ID)
	first := f.mustStore("first", scope)
	for _, status := range []string{"active", "disabled"} {
		if _, err := f.pool.Exec(f.ctx, `UPDATE stores SET status=$1 WHERE org_id=$2 AND id=$3`, status, f.org.ID, first.ID); err != nil {
			t.Fatal("change store status")
		}
		_, err := f.cat.CreateStore(f.ctx, f.org.ID, "builtin", "duplicate", scope)
		if err == nil {
			t.Fatal("second builtin store accepted at same owner scope")
		}
		classAppErr(t, err, apperr.ClassAlreadyExists)
		if strings.Contains(err.Error(), first.ID.String()) || err.Error() != "a builtin store already exists at this scope" {
			t.Fatal("duplicate store error disclosed details")
		}
	}
	for range 2 {
		if _, err := f.cat.CreateStore(f.ctx, f.org.ID, "vault", "external", scope); err != nil {
			t.Fatal("external store incorrectly restricted")
		}
	}
	ws := f.mustWorkspace("other")
	if _, err := f.cat.CreateStore(f.ctx, f.org.ID, "builtin", "other", tenancy.Scope{Level: tenancy.LevelWorkspace, ID: ws.ID}); err != nil {
		t.Fatal("other scope incorrectly restricted")
	}
}
