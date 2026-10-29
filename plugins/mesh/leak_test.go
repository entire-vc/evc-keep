package mesh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

// newProvider wires a provider to a stub with a debug-level logger writing
// to buf, so a body logged at any level shows up.
func newProvider(t *testing.T, s *stubMesh, buf *bytes.Buffer) *mesh.Provider {
	t.Helper()
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p, err := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: s.agent, Token: stubToken, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The canary rides in the POST answer (as the key) and in every failure body.
// It must not surface in a log line, an error text, or the Status/KeyID.
func TestCanaryDoesNotSurface(t *testing.T) {
	c := canary.New()
	agent := uuid.NewString()
	s := newStub(t, agent, c.Value(0))
	s.note = c.Value(2) // rides in every list and POST answer
	var logs bytes.Buffer
	p := newProvider(t, s, &logs)
	ctx := context.Background()

	var errTexts []string
	iss, err := p.Issue(ctx, rotation.IssueRequest{Subject: "sage", RunID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if iss.Value.Len() != len(c.Value(0)) {
		t.Fatalf("value not carried: len %d", iss.Value.Len())
	}
	if _, err := p.Check(ctx, iss.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := p.Revoke(ctx, iss.KeyID); err != nil {
		t.Fatal(err)
	}

	// Failure bodies that echo the canary.
	for _, code := range []int{400, 401, 403, 404, 429, 500, 502} {
		s.mu.Lock()
		s.fail, s.failTxt = code, `{"error":"`+c.Value(1)+`","key":"`+c.Value(0)+`"}`
		s.mu.Unlock()
		_, e1 := p.Issue(ctx, rotation.IssueRequest{Subject: "sage", RunID: uuid.New()})
		_, e2 := p.Check(ctx, uuid.NewString())
		e3 := p.Revoke(ctx, uuid.NewString())
		_, _, e4 := p.Current(ctx, "sage")
		for _, e := range []error{e1, e2, e3, e4} {
			if e == nil {
				continue
			}
			errTexts = append(errTexts, e.Error())
		}
	}
	all := logs.String() + "\n" + strings.Join(errTexts, "\n") + "\n" + iss.KeyID + "\n" + iss.Value.String()
	if c.In(all) {
		t.Fatalf("canary surfaced in log/error text:\n%s", all)
	}
	if len(errTexts) == 0 {
		t.Fatal("no errors observed: the failure path was not exercised")
	}
	// Positive control: the logger does record things.
	if !strings.Contains(logs.String(), "issue") {
		t.Fatalf("issue not journaled: %q", logs.String())
	}
}

// The service token must not surface when a Config or Provider is printed or
// logged by a caller, nor in an error.
func TestTokenDoesNotSurface(t *testing.T) {
	c := canary.New()
	agent := uuid.NewString()
	cfg := mesh.Config{BaseURL: "http://127.0.0.1:1", AgentID: agent, Token: mesh.Token(c.Value(0))}
	p, err := mesh.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	l.Info("cfg", "cfg", cfg, "p", p, "tok", cfg.Token)
	out := fmt.Sprintf("%v|%+v|%#v|%s|%v|%+v|%#v|%v|%+v", cfg, cfg, cfg, cfg.Token, p, p, cfg, *p, *p)
	// Config now holds a func (TokenSource), which no JSON encoder can marshal:
	// encode the token on its own so the MarshalText path stays covered.
	if j, err := json.Marshal(map[string]any{"t": cfg.Token, "l": []mesh.Token{cfg.Token}}); err != nil {
		t.Fatal(err)
	} else {
		out += string(j)
	}
	var tb bytes.Buffer
	slog.New(slog.NewTextHandler(&tb, nil)).Info("p", "p", p, "pv", *p)
	out += tb.String()
	_, e1 := p.Issue(context.Background(), rotation.IssueRequest{Subject: "x", RunID: uuid.New()})
	if e1 == nil {
		t.Fatal("unreachable backend gave no error")
	}
	if c.In(buf.String() + out + e1.Error()) {
		t.Fatalf("token surfaced: %s %s", buf.String(), out)
	}
}

func TestOrphanKeyRevoked(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "") // POST creates a key but gives no value
	p := newProvider(t, s, &bytes.Buffer{})
	if _, err := p.Issue(context.Background(), rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, st := range s.keys {
		if st == "active" {
			t.Fatalf("key %s left active", id)
		}
	}
	if len(s.keys) != 1 {
		t.Fatalf("expected one created key, got %d", len(s.keys))
	}
}

// The token goes through the provider's own logger and error paths: a good
// run, backend failures, and a transport failure (closed server).
func TestTokenNotInProviderOutput(t *testing.T) {
	c := canary.New()
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tok := mesh.Token(c.Value(0))
	run := func(base string) []string {
		p, err := mesh.New(mesh.Config{BaseURL: base, AgentID: agent, Token: tok, Log: log})
		if err != nil {
			t.Fatal(err)
		}
		var texts []string
		ctx := context.Background()
		for _, e := range []error{
			func() error { _, e := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); return e }(),
			func() error { _, e := p.Check(ctx, uuid.NewString()); return e }(),
			p.Revoke(ctx, uuid.NewString()),
			func() error { _, _, e := p.Current(ctx, "x"); return e }(),
		} {
			if e != nil {
				texts = append(texts, e.Error())
			}
		}
		return texts
	}
	texts := run(s.srv.URL) // wrong token: denied, every call fails
	s.srv.Close()
	texts = append(texts, run(s.srv.URL)...) // transport failure
	// A transport error quotes the request URL: a canary in the base path
	// must not come back through an error or the log.
	texts = append(texts, run(s.srv.URL+"/"+c.Value(1))...)
	if len(texts) < 12 {
		t.Fatalf("failure paths not exercised: %d errors", len(texts))
	}
	if c.In(logs.String() + strings.Join(texts, "\n")) {
		t.Fatalf("token or URL surfaced: %s %v", logs.String(), texts)
	}
}

// A redirect must not carry the bearer token anywhere.
func TestRedirectDoesNotCarryToken(t *testing.T) {
	agent := uuid.NewString()
	var got string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer target.Close()
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+r.URL.Path) //nolint:gosec // test stub redirect
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer hop.Close()
	for _, hc := range []*http.Client{nil, {Timeout: time.Second}} {
		got = ""
		p, err := mesh.New(mesh.Config{BaseURL: hop.URL, AgentID: agent, Token: stubToken, HTTP: hc})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Issue(context.Background(), rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); !errors.Is(err, rotation.ErrUnavailable) {
			t.Fatalf("redirect was followed or misclassified: %v", err)
		}
		if got != "" {
			t.Fatalf("token reached the redirect target: %q", got)
		}
	}
}
