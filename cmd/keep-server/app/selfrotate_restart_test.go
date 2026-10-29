package app

import (
	"context"
	"fmt"
	"testing"

	"github.com/entire-vc/evc-keep/internal/restart"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	"github.com/entire-vc/evc-keep/pkg/provider/svctoken"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// The adapter the plugin gets: it queues a restart for the configured org and
// lane with the fingerprint of the active token, and the row holds names, a
// version label and that fingerprint only: not the token.
func TestSelfRotateRestartsQueueCarriesNoTokenValue(t *testing.T) {
	pool := testPool(t)
	org := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "o-"+org.String()); err != nil {
		t.Fatal(err)
	}
	c := canary.New()
	store, err := svctoken.New(memory.New(nil), "mesh-service-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Seed(context.Background(), secret.New([]byte("ext_"+c.Value(0)))); err != nil {
		t.Fatal(err)
	}
	q := &selfRotateRestarts{
		queue: restart.NewRepo(pool), org: org, lane: "Hugh", store: store,
		fpKey: func(context.Context) (fingerprint.Key, error) { return fingerprint.GenerateKey("testkey") },
	}
	id, err := q.Enqueue(context.Background(), "key-9")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	var row string
	if err := pool.QueryRow(context.Background(), `SELECT r::text FROM restart_requests r WHERE request_id = $1`, id).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if !c.In(fmt.Sprint("ext_"+c.Value(0))) || c.In(row) {
		t.Fatalf("the token reached the queue row (or the detector is blind): %s", row)
	}
	var lane, version, fp string
	if err := pool.QueryRow(context.Background(), `SELECT lane, key_version, fingerprint FROM restart_requests WHERE request_id = $1 AND org_id = $2`, id, org).Scan(&lane, &version, &fp); err != nil {
		t.Fatal(err)
	}
	if lane != "Hugh" || version != "key-9" || !fingerprint.Valid(fp) {
		t.Fatalf("row: lane=%q version=%q fingerprint=%q", lane, version, fp)
	}
	applied, final, err := q.Outcome(context.Background(), id)
	if err != nil || applied || final {
		t.Fatalf("open request: applied=%v final=%v err=%v", applied, final, err)
	}
	// Another organization's id is unknown to this binding.
	other := &selfRotateRestarts{queue: q.queue, org: uuid.New(), lane: "Hugh", store: store, fpKey: q.fpKey}
	if _, _, err := other.Outcome(context.Background(), id); err == nil {
		t.Fatal("a request of another organization was readable")
	}
}
