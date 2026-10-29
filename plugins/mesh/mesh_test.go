package mesh_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

func TestDualKeyLifecycle(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "fake-key-value")
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()

	if p.Kind() != mesh.Kind || !p.Capabilities().DualKey {
		t.Fatal("kind or capabilities wrong")
	}
	a, err := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{a.KeyID, b.KeyID} {
		if st, err := p.Check(ctx, id); err != nil || !st.Active {
			t.Fatalf("key %s should be active: %v %v", id, st, err)
		}
	}
	// two active keys: none is "the" key
	if _, ok, err := p.Current(ctx, "x"); err != nil || ok {
		t.Fatalf("Current with two keys: ok=%v err=%v", ok, err)
	}
	if err := p.Revoke(ctx, a.KeyID); err != nil {
		t.Fatal(err)
	}
	if st, err := p.Check(ctx, a.KeyID); err != nil || st.Active {
		t.Fatalf("revoked key must be inactive: %v %v", st, err)
	}
	if id, ok, err := p.Current(ctx, "x"); err != nil || !ok || id != b.KeyID {
		t.Fatalf("Current: %q %v %v", id, ok, err)
	}
	// idempotent, and an unknown key revokes cleanly
	if err := p.Revoke(ctx, a.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := p.Revoke(ctx, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
}

// An empty or foreign-shaped key id is a closed error and makes no call.
func TestBadKeyIDClosed(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()
	live, _ := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()})
	for _, id := range []string{
		"", "../keys", live.KeyID + "/../" + live.KeyID, "not-a-uuid",
		"{" + live.KeyID + "}", // non-canonical form of a live id
		upper(live.KeyID),
	} {
		if st, err := p.Check(ctx, id); !errors.Is(err, rotation.ErrNotFound) || st.Active {
			t.Errorf("Check(%q) = %v, %v", id, st, err)
		}
		if err := p.Revoke(ctx, id); !errors.Is(err, rotation.ErrNotFound) {
			t.Errorf("Revoke(%q) = %v", id, err)
		}
	}
	// the live key was not touched
	if st, err := p.Check(ctx, live.KeyID); err != nil || !st.Active {
		t.Fatalf("live key damaged: %v %v", st, err)
	}
	// a well-formed id of another agent's key is not listed: not found
	if _, err := p.Check(ctx, uuid.NewString()); !errors.Is(err, rotation.ErrNotFound) {
		t.Fatalf("foreign key: %v", err)
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func TestErrorClasses(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()
	for code, want := range map[int]error{
		401: rotation.ErrDenied, 403: rotation.ErrDenied,
		500: rotation.ErrUnavailable, 429: rotation.ErrUnavailable,
	} {
		s.mu.Lock()
		s.fail = code
		s.mu.Unlock()
		if _, err := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); !errors.Is(err, want) {
			t.Errorf("%d: %v", code, err)
		}
	}
	s.mu.Lock()
	s.fail = 0
	s.mu.Unlock()
	// a bad token is denied
	bad, _ := mesh.New(mesh.Config{BaseURL: s.srv.URL, AgentID: agent, Token: "ext_wrong"})
	if err := bad.Revoke(ctx, uuid.NewString()); !errors.Is(err, rotation.ErrDenied) {
		t.Errorf("bad token: %v", err)
	}
}

func TestIssueRejectsBadAnswer(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "") // empty value
	p := newProvider(t, s, &bytes.Buffer{})
	if _, err := p.Issue(context.Background(), rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("empty value accepted: %v", err)
	}
}

func TestNewRejectsConfig(t *testing.T) {
	good := mesh.Config{BaseURL: "https://mesh.example", AgentID: uuid.NewString(), Token: "t"}
	if _, err := mesh.New(good); err != nil {
		t.Fatal(err)
	}
	for _, mod := range []func(*mesh.Config){
		func(c *mesh.Config) { c.Token = "" },
		func(c *mesh.Config) { c.AgentID = "../x" },
		func(c *mesh.Config) { c.BaseURL = "ftp://x" },
		func(c *mesh.Config) { c.BaseURL = "" },
		func(c *mesh.Config) { c.BaseURL = "http://mesh.example" }, // plain http off loopback
	} {
		c := good
		mod(&c)
		if _, err := mesh.New(c); !errors.Is(err, mesh.ErrConfig) {
			t.Errorf("config accepted: %+v", c.BaseURL)
		}
	}
}

func TestBadKeyIDFromBackend(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	s.badID = "NOT-A-UUID"
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()
	if _, err := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("Issue accepted a malformed key id: %v", err)
	}
	// a clean list but a malformed id in the POST answer
	s.badID, s.postBad = "", "NOT-A-UUID"
	if _, err := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("Issue accepted a malformed key id in the answer: %v", err)
	}
	s.badID, s.postBad = "NOT-A-UUID", ""
	if _, err := p.Check(ctx, uuid.NewString()); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("Check accepted a malformed list: %v", err)
	}
	if _, ok, err := p.Current(ctx, "x"); ok || !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("Current accepted a malformed list: %v %v", ok, err)
	}
}

func TestCurrentNoneActive(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()
	if id, ok, err := p.Current(ctx, "x"); err != nil || ok || id != "" {
		t.Fatalf("empty set: %q %v %v", id, ok, err)
	}
	a, _ := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()})
	_ = p.Revoke(ctx, a.KeyID)
	if id, ok, err := p.Current(ctx, "x"); err != nil || ok || id != "" {
		t.Fatalf("all revoked: %q %v %v", id, ok, err)
	}
}

// An unusable POST answer that names a key Mesh already held (the live one)
// must not revoke it: only a key new since the call is ended.
func TestOrphanRevokeSkipsForeignKeyID(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()
	live, err := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.postID, s.value = live.KeyID, "" // the answer points at the live key, no value
	s.mu.Unlock()
	if _, err := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("Issue: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delSeen != 0 || s.keys[live.KeyID] != "active" {
		t.Fatalf("live key touched: deletes=%d status=%q", s.delSeen, s.keys[live.KeyID])
	}
}

// A 404 on DELETE for a key the list still shows is not "revoked".
func TestRevoke404ConfirmedByList(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()
	k, err := p.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.del404 = true
	s.mu.Unlock()
	if err := p.Revoke(ctx, k.KeyID); !errors.Is(err, rotation.ErrUnavailable) {
		t.Fatalf("404 for a listed key counted as revoked: %v", err)
	}
	// a key the list does not show is revoked, idempotently
	if err := p.Revoke(ctx, uuid.NewString()); err != nil {
		t.Fatalf("unlisted key: %v", err)
	}
}
