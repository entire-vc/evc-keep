package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/rotation"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// engineFakes are the collaborators of a real rotation engine: three carriers
// and the failures a test plants. Every failure text carries the canary.
type engineFakes struct {
	mu        sync.Mutex
	deployErr map[string]error
	revokeErr error
	revokes   int
	prepares  int
}

func engineCarrier(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func (f *engineFakes) Prepare(context.Context, rotation.Ref, uuid.UUID) (rotation.Version, error) {
	f.mu.Lock()
	f.prepares++
	f.mu.Unlock()
	return rotation.Version{Old: "1", New: "2", Fingerprint: rotFP, Length: 42}, nil
}
func (f *engineFakes) List(context.Context, rotation.Ref) ([]rotation.Carrier, error) {
	return []rotation.Carrier{{ID: engineCarrier(1)}, {ID: engineCarrier(2)}, {ID: engineCarrier(3)}}, nil
}
func (f *engineFakes) Deploy(_ context.Context, _ rotation.Ref, _ uuid.UUID, c rotation.Carrier, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deployErr[c.ID]
}
func (f *engineFakes) Verify(context.Context, rotation.Ref, rotation.Carrier, string) (rotation.Report, error) {
	return rotation.Report{Fingerprint: rotFP, Healthy: true}, nil
}
func (f *engineFakes) Revoke(context.Context, rotation.Ref, uuid.UUID, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes++
	return f.revokeErr
}
func (f *engineFakes) Open(context.Context, rotation.IncidentRecord) error    { return nil }
func (f *engineFakes) Resolve(context.Context, rotation.IncidentRecord) error { return nil }

func (f *engineFakes) deps() rotation.Deps {
	return rotation.Deps{Versions: f, Carriers: f, Deployer: f, Verifier: f, Revoker: f, Incident: f}
}

// poll reads the status until the run is terminal.
func (f *rotateFixture) poll(id string) (RotateResult, string) {
	f.t.Helper()
	for i := 0; i < 200; i++ {
		rec := f.do(http.MethodGet, f.path+"/"+id, f.bearer, nil)
		var got RotateResult
		if rec.Code == http.StatusOK {
			dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&got); err != nil {
				f.t.Fatalf("not the closed shape: %v", err)
			}
			return got, f.dump(rec, rec.Body.String())
		}
		if rec.Code != http.StatusAccepted {
			f.t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatal("run did not finish")
	return RotateResult{}, ""
}

func startRun(t *testing.T, f *rotateFixture) string {
	t.Helper()
	rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"})
	var got RotateResult
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.RequestID == "" {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	return got.RequestID
}

// One failing carrier: the run fails, no version or fingerprint is reported,
// the failed carrier is stale, the old version is not revoked, and the text
// the carrier failed with (it holds the canary) reaches no surface.
func TestRotate_OneFailedCarrierActivatesNothing(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	if !c.In("x"+v) || !c.In(strings.ToUpper(v)) {
		t.Fatal("canary detector is blind")
	}
	fakes := &engineFakes{deployErr: map[string]error{engineCarrier(2): errors.New("deploy of " + v)}}
	svc := rotation.NewService(rotation.New(testPool(t), fakes.deps())).WithJournal(audit.NewJournal(testPool(t)))
	f := newRotateFixture(t, svc, nil)
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Rotations: svc, Catalog: unlimitedCatalog})
	res, dump := f.poll(startRun(t, f))
	if res.OK || res.ErrorClass != "deploy_failed" || res.Version != "" || res.Fingerprint != "" {
		t.Fatalf("a failed carrier must activate nothing: %+v", res)
	}
	stale := map[string]string{}
	for _, cr := range res.Carriers {
		stale[cr.CarrierID] = cr.State
	}
	if stale[engineCarrier(2)] != "stale" || len(stale) != 3 {
		t.Fatalf("the failed carrier must be stale: %+v", res.Carriers)
	}
	svc.Wait()
	fakes.mu.Lock()
	revokes := fakes.revokes
	fakes.mu.Unlock()
	if revokes != 0 {
		t.Fatalf("old version revoked %d times after a failed carrier", revokes)
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("interception saw no log; the test proves nothing")
	}
	if c.In(dump) {
		t.Fatalf("canary reached a response, a header or the log (%d bytes inspected)", len(dump))
	}
}

func TestRotate_AllCarriersConfirmedActivates(t *testing.T) {
	fakes := &engineFakes{deployErr: map[string]error{}}
	svc := rotation.NewService(rotation.New(testPool(t), fakes.deps())).WithJournal(audit.NewJournal(testPool(t)))
	f := newRotateFixture(t, svc, nil)
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Rotations: svc, Catalog: unlimitedCatalog})
	res, _ := f.poll(startRun(t, f))
	if !res.OK || res.Version != "2" || res.Fingerprint != rotFP || res.ErrorClass != "" {
		t.Fatalf("got %+v", res)
	}
	for _, cr := range res.Carriers {
		if cr.Phase != "verify" || cr.State != "ok" {
			t.Fatalf("every carrier is verified once the run is done: %+v", res.Carriers)
		}
	}
	svc.Wait()
	if fakes.revokes != 1 {
		t.Fatalf("revokes=%d", fakes.revokes)
	}
}

// A secret whose old key is still alive: a new rotate over HTTP is 409
// revoke_pending, the answer rotationAppError gives for the real engine's
// ErrRevokePending, and the body carries no value.
func TestRotate_RevokePendingIs409OverHTTP(t *testing.T) {
	c := canary.New()
	v := c.Value(1)
	fakes := &engineFakes{deployErr: map[string]error{}, revokeErr: errors.New("revoke of " + v)}
	svc := rotation.NewService(rotation.New(testPool(t), fakes.deps())).WithJournal(audit.NewJournal(testPool(t)))
	f := newRotateFixture(t, svc, nil)
	f.router = NewRouter(obs.New(f.logbuf), f.pool, Deps{Rotations: svc, Catalog: unlimitedCatalog})
	startRun(t, f)
	svc.Wait()
	rec := f.do(http.MethodPost, f.path, f.bearer, map[string]any{"mode": "generate"})
	var got struct {
		ErrorClass string `json:"error_class"`
	}
	if rec.Code != http.StatusConflict || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.ErrorClass != "revoke_pending" {
		t.Fatalf("want 409 revoke_pending, got %d %s", rec.Code, rec.Body.String())
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("interception saw no log; the test proves nothing")
	}
	if d := f.dump(rec, rec.Body.String()); c.In(d) {
		t.Fatalf("canary reached the response, a header or the log (%d bytes inspected)", len(d))
	}
}
