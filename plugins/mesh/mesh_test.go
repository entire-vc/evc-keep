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

// Only the exact entry "primary" is tolerated beside UUIDs in Mesh's list.
func TestPrimaryIsExact(t *testing.T) {
	for _, id := range []string{"pri", "primary2", "Primary", "p1"} {
		s := newStub(t, uuid.NewString(), "v")
		s.badID = id
		p := newProvider(t, s, &bytes.Buffer{})
		if _, ok, err := p.Current(context.Background(), "x"); ok || !errors.Is(err, mesh.ErrBadAnswer) {
			t.Errorf("list entry %q accepted: %v %v", id, ok, err)
		}
	}
}

// The original key "primary" is the current key while it is the only active
// one, under the plugin's alias (this replaces the earlier rule that an active
// "primary" is never current, which left it unrevoked after a rotation). With a
// second active key there is no current key, as before.
func TestActivePrimaryIsCurrentAsAlias(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	s.primaryOn = true
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()
	id, ok, err := p.Current(ctx, "x")
	if err != nil || !ok || id != mesh.PrimaryAlias(agent) {
		t.Fatalf("an only active primary is not current under its alias: %q %v %v", id, ok, err)
	}
	if !rotation.ValidKeyID(id) {
		t.Fatalf("the alias is not a key id the core accepts: %q", id)
	}
	s.mu.Lock()
	s.keys[uuid.NewString()] = "active"
	s.mu.Unlock()
	if id, ok, err := p.Current(ctx, "x"); err != nil || ok || id != "" {
		t.Fatalf("primary and an issued key both active, still a current key: %q %v %v", id, ok, err)
	}
}

// The alias is part of the ledger format: a run records it before Issue and
// revokes by it later, possibly in another build. A changed namespace or name
// would orphan those records, so the value is pinned. It is per agent.
func TestPrimaryAliasGolden(t *testing.T) {
	const agent = "6f0a3c1e-1b2d-4c3e-8f4a-5b6c7d8e9f00"
	if got := mesh.PrimaryAlias(agent); got != "325d9dc1-7084-5031-a6eb-b4cc73d6a62c" {
		t.Fatalf("PrimaryAlias changed: %s", got)
	}
	u := uuid.MustParse(mesh.PrimaryAlias(agent))
	if u.Version() != 5 {
		t.Fatalf("alias version %d, want 5 (name-based)", u.Version())
	}
	if mesh.PrimaryAlias(agent) == mesh.PrimaryAlias(uuid.NewString()) {
		t.Fatal("two agents share an alias")
	}
}

// Check and Revoke turn the alias back into "primary": the DELETE goes to
// .../keys/primary, and Check reads the "primary" entry of the list.
func TestPrimaryAliasCheckAndRevoke(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	s.primaryOn = true
	s.keys[uuid.NewString()] = "active" // the new key, so primary is not the last one
	p := newProvider(t, s, &bytes.Buffer{})
	ctx := context.Background()
	alias := mesh.PrimaryAlias(agent)

	if st, err := p.Check(ctx, alias); err != nil || !st.Active {
		t.Fatalf("Check(alias) before revoke: %+v %v", st, err)
	}
	if err := p.Revoke(ctx, alias); err != nil {
		t.Fatalf("Revoke(alias): %v", err)
	}
	s.mu.Lock()
	ids, on := append([]string(nil), s.delIDs...), s.primaryOn
	s.mu.Unlock()
	if len(ids) != 1 || ids[0] != "primary" || on {
		t.Fatalf("DELETE ids %v, primary active %t", ids, on)
	}
	if st, err := p.Check(ctx, alias); err != nil || st.Active {
		t.Fatalf("Check(alias) after revoke: %+v %v", st, err)
	}
}

// Mesh refuses to end the last active key (409): that is an error, not "revoked".
func TestPrimaryAliasRevokeLastKeyIsError(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	s.primaryOn = true
	p := newProvider(t, s, &bytes.Buffer{})
	if err := p.Revoke(context.Background(), mesh.PrimaryAlias(agent)); err == nil {
		t.Fatal("a refused revoke of the last key reported success")
	}
	if !s.primaryOn {
		t.Fatal("stub: primary ended")
	}
}

// A 404 for "primary" is not believed: Mesh always lists the original key, so
// the re-check after the 404 must find it under the alias and refuse.
func TestPrimaryAliasRevoke404IsNotRevoked(t *testing.T) {
	agent := uuid.NewString()
	s := newStub(t, agent, "v")
	s.primaryOn = true
	s.keys[uuid.NewString()] = "active"
	s.del404 = true
	p := newProvider(t, s, &bytes.Buffer{})
	if err := p.Revoke(context.Background(), mesh.PrimaryAlias(agent)); !errors.Is(err, rotation.ErrUnavailable) {
		t.Fatalf("a 404 on a listed primary counted as revoked: %v", err)
	}
}

// A Mesh key whose own id equals the alias would be taken for the original
// key: the list is refused, and an issue answer naming the alias is a bad
// answer that ends nothing (in particular not "primary").
func TestPrimaryAliasCollisionRefused(t *testing.T) {
	agent := uuid.NewString()
	alias := mesh.PrimaryAlias(agent)
	ctx := context.Background()

	s := newStub(t, agent, "v")
	s.badID = alias
	p := newProvider(t, s, &bytes.Buffer{})
	if _, _, err := p.Current(ctx, "x"); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("a listed key with the alias id accepted: %v", err)
	}
	if _, err := p.Check(ctx, alias); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("Check over a list with the alias id: %v", err)
	}

	s2 := newStub(t, agent, "v")
	s2.primaryOn = true
	s2.postBad = alias
	p2 := newProvider(t, s2, &bytes.Buffer{})
	if _, err := p2.Issue(ctx, rotation.IssueRequest{Subject: "x", RunID: uuid.New()}); !errors.Is(err, mesh.ErrBadAnswer) {
		t.Fatalf("an issue answer naming the alias accepted: %v", err)
	}
	s2.mu.Lock()
	defer s2.mu.Unlock()
	if s2.delSeen != 0 || !s2.primaryOn {
		t.Fatalf("a bad issue answer ended a key: DELETE %v, primary active %t", s2.delIDs, s2.primaryOn)
	}
}

// revoked_at is null for an active key; an empty string is not "active".
func TestEmptyRevokedAtIsNotActive(t *testing.T) {
	s := newStub(t, uuid.NewString(), "v")
	s.emptyRev = uuid.NewString()
	p := newProvider(t, s, &bytes.Buffer{})
	if id, ok, err := p.Current(context.Background(), "x"); err != nil || ok || id != "" {
		t.Fatalf("a key with revoked_at \"\" counted as active: %q %v %v", id, ok, err)
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
