package api

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/google/uuid"
)

// readerVault adds the metadata reader to touchVault; every call panics, so a
// request that reaches the reader or storage is seen.
type readerVault struct{ touchVault }

func (readerVault) MetadataSecret(context.Context, string, string, string) (MeshSecretMeta, error) {
	panic("the reader was reached")
}

// Production wiring must give the probe a reader and a real journal: without
// either it is 503 "metadata unavailable", before anything is read, signed or
// stored.
func TestMetadataNeedsReaderAndJournal(t *testing.T) {
	for name, tc := range map[string]struct {
		vault MeshVault
		aud   audit.Journaler
	}{
		"no reader":  {vault: touchVault{}, aud: audit.NewJournal(nil)},
		"no journal": {vault: readerVault{}, aud: nil},
	} {
		m := preauthRoutes(5)
		m.deps.Vault, m.aud = tc.vault, tc.aud
		r := httptest.NewRequest(http.MethodGet, "/orgs/"+uuid.NewString()+"/mesh/secrets/k/metadata", nil)
		r.TLS = &tls.ConnectionState{}
		rec, touched := serve((&metadataRoutes{meshRoutes: m}).handleMetadataSecret, r)
		if touched || rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"metadata unavailable"`) {
			t.Errorf("%s: status %d touched=%v", name, rec.Code, touched)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: answer is cacheable", name)
		}
	}
}

// The refactor that gave the probe its own texts left PUT and resolve with
// the ones they always had; the metadata texts are not those.
func TestMeshLegacyActorMessagesUnchanged(t *testing.T) {
	want := actorMsgs{db: "database not reachable", journal: "secret storage not reachable", limited: "too many requests; retry later"}
	if secretActorLegacy != want {
		t.Fatal("the texts PUT and resolve answer with changed")
	}
	if metadataActorMsgs == want {
		t.Fatal("the probe shares the legacy texts")
	}
}
