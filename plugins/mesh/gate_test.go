package mesh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

// gateStub is a Mesh stub for the card calls. It records every request.
type gateStub struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls []string          // "METHOD path"
	bodys map[string][]byte // path -> last body
	fail  map[string]int    // path suffix -> status to answer
	card  string
	note  string // rides in every answer body
}

func newGateStub(t *testing.T) *gateStub {
	t.Helper()
	s := &gateStub{bodys: map[string][]byte{}, fail: map[string]int{}, card: uuid.NewString()}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls = append(s.calls, r.Method+" "+r.URL.Path)
		s.bodys[r.URL.Path] = raw
		if r.Header.Get("Authorization") != "Bearer "+stubToken {
			http.Error(w, s.note, http.StatusUnauthorized)
			return
		}
		for suf, code := range s.fail {
			if strings.HasSuffix(r.URL.Path, suf) {
				http.Error(w, s.note, code)
				return
			}
		}
		// Mesh refuses an API arm without a stated default, a deadline or the
		// predicate with 422 (domain.ArmHumanGateInput.Validate).
		if strings.HasSuffix(r.URL.Path, "/human-gate") {
			var arm struct {
				RecommendedDefault string          `json:"recommended_default"`
				Deadline           string          `json:"deadline"`
				Predicate          json.RawMessage `json:"predicate"`
			}
			if json.Unmarshal(raw, &arm) != nil || arm.RecommendedDefault == "" || arm.Deadline == "" || len(arm.Predicate) == 0 {
				http.Error(w, s.note, http.StatusUnprocessableEntity)
				return
			}
			// It also refuses an ask whose checklist says nobody needs to be
			// asked: credential held, reversible, not blocked, nothing a
			// customer sees (domain.GateArmPredicate.Decide, refused_self_serve).
			var p struct {
				Credential bool `json:"credential_exists"`
				Reversible bool `json:"reversible"`
				Blocked    bool `json:"blocked_by_other_task"`
				Customer   bool `json:"customer_visible_now"`
			}
			if json.Unmarshal(arm.Predicate, &p) != nil || (p.Credential && p.Reversible && !p.Blocked && !p.Customer) {
				http.Error(w, s.note, http.StatusUnprocessableEntity)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": s.card, "note": s.note})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"note": s.note})
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *gateStub) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func newGates(t *testing.T, s *gateStub, buf *bytes.Buffer) (*mesh.Gates, string, string) {
	t.Helper()
	project, cancelled := uuid.NewString(), uuid.NewString()
	g, err := mesh.NewGates(mesh.GateConfig{
		BaseURL: s.srv.URL, ProjectID: project, CancelStatusID: cancelled,
		TokenSource: func(context.Context) (mesh.Token, error) { return mesh.Token(stubToken), nil },
		Log:         slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, project, cancelled
}

func spec() gatecard.Spec {
	return gatecard.Spec{Title: "Approve deploy of DB_URL", Body: "request 1", ExternalRef: "keep:approval:1",
		RequestHash: strings.Repeat("ab", 32), Deadline: time.Now().Add(time.Hour)}
}

func TestGatesCreateBindsHashAndArmsGate(t *testing.T) {
	s := newGateStub(t)
	var buf bytes.Buffer
	g, project, _ := newGates(t, s, &buf)
	id, err := g.Create(context.Background(), spec())
	if err != nil || id != s.card {
		t.Fatalf("Create = %q, %v", id, err)
	}
	want := []string{"POST /api/v1/projects/" + project + "/tasks", "PUT /api/v1/tasks/" + id + "/external-ref", "POST /api/v1/tasks/" + id + "/human-gate"}
	got := s.seen()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	var ref map[string]string
	_ = json.Unmarshal(s.bodys["/api/v1/tasks/"+id+"/external-ref"], &ref)
	if ref["external_hash"] != strings.Repeat("ab", 32) || ref["external_ref"] != "keep:approval:1" {
		t.Fatalf("external-ref body = %v", ref)
	}
	var gate map[string]any
	_ = json.Unmarshal(s.bodys["/api/v1/tasks/"+id+"/human-gate"], &gate)
	if gate["deadline"] == nil || gate["reason"] == nil {
		t.Fatalf("human-gate body lacks deadline or reason: %v", gate)
	}
}

// A card that cannot be armed would never be answered in a way Keep trusts:
// it must be cancelled, and Create must fail.
func TestGatesCreateCancelsCardThatCannotBeArmed(t *testing.T) {
	s := newGateStub(t)
	s.fail["/human-gate"] = http.StatusServiceUnavailable
	var buf bytes.Buffer
	g, _, _ := newGates(t, s, &buf)
	if id, err := g.Create(context.Background(), spec()); !errors.Is(err, gatecard.ErrUnavailable) || id != "" {
		t.Fatalf("Create = %q, %v; want ErrUnavailable", id, err)
	}
	last := s.seen()[len(s.seen())-1]
	if last != "POST /api/v1/tasks/"+s.card+"/move" {
		t.Fatalf("last call = %q, want the cancelling move", last)
	}
}

func TestGatesRefusalsAreClassed(t *testing.T) {
	s := newGateStub(t)
	var buf bytes.Buffer
	g, _, _ := newGates(t, s, &buf)
	s.fail["/move"] = http.StatusForbidden // human_gate_frozen
	if err := g.Cancel(context.Background(), s.card, "lapsed"); !errors.Is(err, gatecard.ErrRefused) {
		t.Fatalf("Cancel on 403 = %v, want ErrRefused", err)
	}
	s.fail["/move"] = http.StatusBadGateway
	if err := g.Cancel(context.Background(), s.card, "lapsed"); !errors.Is(err, gatecard.ErrUnavailable) {
		t.Fatalf("Cancel on 502 = %v, want ErrUnavailable", err)
	}
	s.fail["/move"] = 0
	delete(s.fail, "/move")
	if err := g.Cancel(context.Background(), s.card, "lapsed"); err != nil {
		t.Fatalf("Cancel = %v", err)
	}
	if err := g.Cancel(context.Background(), "not-a-uuid", "x"); !errors.Is(err, gatecard.ErrRefused) {
		t.Fatalf("Cancel(bad id) = %v, want ErrRefused", err)
	}
}

func TestGatesConfigIsStrict(t *testing.T) {
	src := func(context.Context) (mesh.Token, error) { return mesh.Token(stubToken), nil }
	p := uuid.NewString()
	for name, cfg := range map[string]mesh.GateConfig{
		"plain http remote": {BaseURL: "http://mesh.example.com", ProjectID: p, TokenSource: src},
		"no token source":   {BaseURL: "https://mesh.example.com", ProjectID: p},
		"bad project":       {BaseURL: "https://mesh.example.com", ProjectID: "x", TokenSource: src},
		"bad cancel status": {BaseURL: "https://mesh.example.com", ProjectID: p, CancelStatusID: "x", TokenSource: src},
	} {
		if _, err := mesh.NewGates(cfg); !errors.Is(err, mesh.ErrConfig) {
			t.Errorf("%s: err = %v, want ErrConfig", name, err)
		}
	}
}

// The canary rides in every answer body, including failures: it must reach
// neither a log line nor an error text, and the token must not either.
func TestGatesNothingFromMeshSurfaces(t *testing.T) {
	c := canary.New()
	if !c.In("x" + c.Value(0)) {
		t.Fatal("canary detector is blind")
	}
	s := newGateStub(t)
	s.note = c.Value(0)
	var buf bytes.Buffer
	g, _, _ := newGates(t, s, &buf)
	var out []string
	if _, err := g.Create(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	s.fail["/external-ref"] = http.StatusConflict
	_, err := g.Create(context.Background(), spec())
	out = append(out, err.Error())
	s.fail["/move"] = http.StatusInternalServerError
	out = append(out, g.Cancel(context.Background(), s.card, "r").Error(), g.String())
	if buf.Len() == 0 {
		t.Fatal("logger saw nothing; the test proves nothing")
	}
	out = append(out, buf.String())
	for _, o := range out {
		if c.In(o) || strings.Contains(o, stubToken) {
			t.Fatalf("answer text or token surfaced: %q", o)
		}
	}
}

// A redirect would carry the bearer token to another host: it is not followed.
func TestGatesRedirectIsNotFollowed(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer other.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	g, err := mesh.NewGates(mesh.GateConfig{BaseURL: s.URL, ProjectID: uuid.NewString(),
		TokenSource: func(context.Context) (mesh.Token, error) { return mesh.Token(stubToken), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Create(context.Background(), spec()); err == nil {
		t.Fatal("Create succeeded through a redirect")
	}
	if hits != 0 {
		t.Fatalf("redirect target was called %d times", hits)
	}
}

// The gate is armed as a hard gate with the deadline and the full predicate,
// and a cancel names the status it moves to.
func TestGatesBodiesCarryDeadlineClassAndStatus(t *testing.T) {
	s := newGateStub(t)
	var buf bytes.Buffer
	g, _, cancelled := newGates(t, s, &buf)
	sp := spec()
	id, err := g.Create(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	var gate struct {
		Class              string
		Deadline           string
		RecommendedDefault string `json:"recommended_default"`
		Predicate          map[string]any
	}
	if err := json.Unmarshal(s.bodys["/api/v1/tasks/"+id+"/human-gate"], &gate); err != nil {
		t.Fatal(err)
	}
	dl, perr := time.Parse(time.RFC3339, gate.Deadline)
	// The default Mesh applies when nobody answers is a refusal: it arrives as
	// a non-user decision, which Keep refuses anyway, so the request stays undone.
	// The asker does not hold the decision: only a linked person does.
	if gate.Class != "hard" || perr != nil || !dl.Equal(sp.Deadline.Truncate(time.Second)) || len(gate.Predicate) != 8 || gate.RecommendedDefault != "reject" ||
		gate.Predicate["credential_exists"] != false {
		t.Fatalf("human-gate body = %+v (deadline parse %v)", gate, perr)
	}
	if err := g.Cancel(context.Background(), id, "lapsed"); err != nil {
		t.Fatal(err)
	}
	var mv map[string]string
	_ = json.Unmarshal(s.bodys["/api/v1/tasks/"+id+"/move"], &mv)
	if mv["status_id"] != cancelled {
		t.Fatalf("move body = %v, want status %s", mv, cancelled)
	}
}

// Nothing from an unusable answer or a failing dependency reaches the caller.
func TestGatesBadAnswerAndFailingDependencies(t *testing.T) {
	s := newGateStub(t)
	var buf bytes.Buffer
	g, _, _ := newGates(t, s, &buf)
	s.card = "../../admin"
	if id, err := g.Create(context.Background(), spec()); !errors.Is(err, gatecard.ErrUnavailable) || id != "" {
		t.Fatalf("Create with a path-like id = %q, %v", id, err)
	}
	for _, c := range s.seen() {
		if strings.Contains(c, "admin") {
			t.Fatalf("a path-like card id was used in a call: %q", c)
		}
	}
	// A token source that fails with text of its own: the text is not forwarded.
	c := canary.New()
	bad, err := mesh.NewGates(mesh.GateConfig{BaseURL: s.srv.URL, ProjectID: uuid.NewString(),
		TokenSource: func(context.Context) (mesh.Token, error) { return "", errors.New(c.Value(0)) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bad.Create(context.Background(), spec()); !errors.Is(err, gatecard.ErrUnavailable) || c.In(err.Error()) {
		t.Fatalf("token source failure = %v", err)
	}
	// A transport failure: the URL it names is not forwarded.
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	down, err := mesh.NewGates(mesh.GateConfig{BaseURL: url, ProjectID: uuid.NewString(),
		TokenSource: func(context.Context) (mesh.Token, error) { return mesh.Token(stubToken), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = down.Create(context.Background(), spec()); !errors.Is(err, gatecard.ErrUnavailable) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("transport failure = %v", err)
	}
	// Cancel without a configured cancelled status is refused, not sent.
	noCancel, _ := mesh.NewGates(mesh.GateConfig{BaseURL: s.srv.URL, ProjectID: uuid.NewString(),
		TokenSource: func(context.Context) (mesh.Token, error) { return mesh.Token(stubToken), nil }})
	n := len(s.seen())
	if err := noCancel.Cancel(context.Background(), uuid.NewString(), "x"); !errors.Is(err, gatecard.ErrRefused) || len(s.seen()) != n {
		t.Fatalf("Cancel without a status: %v, calls %d->%d", err, n, len(s.seen()))
	}
}
