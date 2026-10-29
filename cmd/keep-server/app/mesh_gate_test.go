package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// fakeGates stands in for the confirmation backend at the events route; its
// own behaviour is tested against a real database in internal/deployment.
type fakeGates struct {
	mu    sync.Mutex
	calls []meshgate.Decided
	out   meshgate.Outcome
	err   error
}

func (g *fakeGates) Handle(_ context.Context, _, _ uuid.UUID, d meshgate.Decided, _ string) (meshgate.Outcome, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, d)
	return g.out, g.err
}

func gateEventBody(ws uuid.UUID, id, decision, hash string) []byte {
	b, _ := json.Marshal(map[string]string{"id": id, "type": "task.gate.decided", "workspace_id": ws.String(),
		"task_id": uuid.NewString(), "decision": decision, "decided_by": uuid.NewString(), "decided_by_type": "user", "external_hash": hash})
	return b
}

func gateRoute(t *testing.T, g api.MeshGates) (*meshFixture, uuid.UUID, string) {
	t.Helper()
	f := newMeshFixtureOn(t, testPool(t), true, func(d *api.MeshDeps) { d.Gates = g })
	ws := uuid.New()
	secret := strings.Repeat("s", 32)
	installedKeepSecret(t, f.install(f.admin, ws, "ext_token_for_tests", secret))
	return f, ws, secret
}

func TestMeshGateEventIsAppliedOnceAndRefusalIsAcknowledged(t *testing.T) {
	g := &fakeGates{out: meshgate.Outcome{Kind: meshgate.Refused, Reason: meshgate.ReasonNotUser}}
	f, ws, secret := gateRoute(t, g)
	body := gateEventBody(ws, "gate-1", "approve", hex.EncodeToString(make([]byte, 32)))
	// A refusal is a 200: Mesh must not retry it or count the connection as failing.
	for i := 0; i < 3; i++ {
		rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body))
		if rec.Code != http.StatusOK {
			t.Fatalf("delivery %d: status = %d, want 200", i, rec.Code)
		}
	}
	if len(g.calls) != 1 || g.calls[0].DecidedByType != "user" || g.calls[0].Decision != "approve" {
		t.Fatalf("gate saw %d calls (%+v), want exactly the one first delivery", len(g.calls), g.calls)
	}
}

// The route's whole job is to hand every field of the answer to the backend
// unchanged: a type forced to "user", a dropped hash or a swapped id would
// void the checks that live behind it.
func TestMeshGateEventPassesEveryFieldUnchanged(t *testing.T) {
	g := &fakeGates{out: meshgate.Outcome{Kind: meshgate.Refused, Reason: meshgate.ReasonNotUser}}
	f, ws, secret := gateRoute(t, g)
	want := meshgate.Decided{TaskID: uuid.NewString(), Decision: "reject: not now", DecidedBy: uuid.NewString(),
		DecidedByType: "agent", ExternalHash: hex.EncodeToString(bytes.Repeat([]byte{9}, 32))}
	body, _ := json.Marshal(map[string]string{"id": "gate-fields", "type": "task.gate.decided", "workspace_id": ws.String(),
		"task_id": want.TaskID, "decision": want.Decision, "decided_by": want.DecidedBy, "decided_by_type": want.DecidedByType,
		"external_hash": want.ExternalHash})
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(g.calls) != 1 || g.calls[0] != want {
		t.Fatalf("backend saw %+v, want %+v", g.calls, want)
	}
}

// Without a confirmation backend a gate answer is acknowledged and ignored.
func TestMeshGateEventWithoutBackendIsAcknowledged(t *testing.T) {
	f, ws, secret := gateRoute(t, nil)
	body := gateEventBody(ws, "gate-nobackend", "approve", hex.EncodeToString(make([]byte, 32)))
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestMeshGateEventNotAppliedIsRetriedNotDropped(t *testing.T) {
	g := &fakeGates{err: errors.New("database down")}
	f, ws, secret := gateRoute(t, g)
	body := gateEventBody(ws, "gate-2", "approve", hex.EncodeToString(make([]byte, 32)))
	rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body))
	if rec.Code != http.StatusServiceUnavailable || f.eventRows(ws) != 0 {
		t.Fatalf("failed apply: status=%d rows=%d, want 503 and the event forgotten", rec.Code, f.eventRows(ws))
	}
	g.err = nil
	g.out = meshgate.Outcome{Kind: meshgate.Approved}
	rec = f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body))
	if rec.Code != http.StatusOK || f.eventRows(ws) != 1 || len(g.calls) != 2 {
		t.Fatalf("retry: status=%d rows=%d calls=%d, want 200, 1 and 2", rec.Code, f.eventRows(ws), len(g.calls))
	}
}

func TestMeshGateEventOnlyForGateType(t *testing.T) {
	g := &fakeGates{}
	f, ws, secret := gateRoute(t, g)
	body := eventBody(ws, "plain-1", "project.created")
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body)); rec.Code != http.StatusOK || len(g.calls) != 0 {
		t.Fatalf("a non-gate event reached the gate backend (%d calls, status %d)", len(g.calls), rec.Code)
	}
}

// TestMeshGateAnswerTextNeverLeaks: the free text of an answer may hold
// anything a person pasted. Through the real backend, on a card Keep does not
// know, it must not come back in the response or the log.
func TestMeshGateAnswerTextNeverLeaks(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	if !c.In("x"+c.Value(1)) || !c.In(hex.EncodeToString([]byte(c.Value(1)))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	ws := uuid.New()
	secret := strings.Repeat("t", 32)
	installedKeepSecret(t, f.install(f.admin, ws, "ext_token_for_tests", secret))
	var surfaces []string
	for i, decided := range []string{"user", "agent"} {
		body, _ := json.Marshal(map[string]string{"id": "leak-" + decided, "type": "task.gate.decided", "workspace_id": ws.String(),
			"task_id": uuid.NewString(), "decision": "approve " + c.Value(i), "decided_by": uuid.NewString(), "decided_by_type": decided,
			"external_hash": hex.EncodeToString([]byte(c.Value(2)))})
		rec := f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, answerDiag(rec))
		}
		surfaces = append(surfaces, rec.Body.String())
		for k, v := range rec.Header() {
			surfaces = append(surfaces, k+": "+strings.Join(v, ","))
		}
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("logger saw nothing; the test proves nothing")
	}
	surfaces = append(surfaces, f.logbuf.String())
	var rows string
	if err := f.pool.QueryRow(context.Background(), `SELECT coalesce(string_agg(t::text, E'\n'),'') FROM mesh_events t`).Scan(&rows); err != nil {
		t.Fatalf("dump events: %v", err)
	}
	surfaces = append(surfaces, rows)
	for i, s := range surfaces {
		if c.In(s) {
			t.Fatalf("answer text leaked on surface #%d (%d bytes); the surface is not printed", i, len(s))
		}
	}
}

// cancelGates cancels the request context mid-apply, as a client timeout or a
// proxy disconnect would, and reports the cancellation as the apply failure.
type cancelGates struct {
	cancel context.CancelFunc
	fakeGates
}

func (g *cancelGates) Handle(ctx context.Context, o, w uuid.UUID, d meshgate.Decided, id string) (meshgate.Outcome, error) {
	g.cancel()
	_, _ = g.fakeGates.Handle(ctx, o, w, d, id)
	return meshgate.Outcome{}, ctx.Err()
}

// A delivery cut off while it is applied must be retried: forgetting the event
// on the cancelled request context fails silently and the repeat is dropped.
func TestMeshGateCancelledDeliveryIsRetryable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := &cancelGates{cancel: cancel}
	f, ws, secret := gateRoute(t, g)
	body := gateEventBody(ws, "gate-cancel", "approve", hex.EncodeToString(make([]byte, 32)))

	r := httptest.NewRequest(http.MethodPost, "/mesh/events", bytes.NewReader(body)).WithContext(ctx)
	r.TLS = &tls.ConnectionState{}
	for k, v := range signedHeaders(ws, secret, time.Now(), body) {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable || f.eventRows(ws) != 0 {
		t.Fatalf("cancelled apply: status=%d rows=%d, want 503 and the event forgotten", rec.Code, f.eventRows(ws))
	}

	rec = f.post("/mesh/events", "", body, signedHeaders(ws, secret, time.Now(), body))
	if rec.Code != http.StatusOK || len(g.calls) != 2 {
		t.Fatalf("retry: status=%d calls=%d, want 200 and the answer applied on the second delivery", rec.Code, len(g.calls))
	}
}
