package deployment

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// stubCards is the Mesh side: it records every card and every cancel, and
// never talks to a live Mesh.
type stubCards struct {
	mu        sync.Mutex
	specs     []gatecard.Spec
	cancelled []string
	cancelErr error
}

func (s *stubCards) Create(_ context.Context, sp gatecard.Spec) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.specs = append(s.specs, sp)
	return uuid.NewString(), nil
}

func (s *stubCards) Cancel(_ context.Context, id, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelErr != nil {
		return s.cancelErr
	}
	s.cancelled = append(s.cancelled, id)
	return nil
}

// roleApprovers is the role check keep-server wires into the gate: the
// approve permission of a user in the secret's scope, read from memberships.
type roleApprovers struct{ ir *identity.Repo }

func (r roleApprovers) CanApprove(ctx context.Context, org, user uuid.UUID, scope tenancy.Scope) (bool, error) {
	perms, err := catalog.PermissionsAt(ctx, r.ir, tenancy.Context{Org: org, Principal: tenancy.Principal{Kind: tenancy.PrincipalUser, ID: user}}, scope)
	if err != nil {
		return false, err
	}
	return perms[identity.PermApprove], nil
}

// grant gives user role in the organization scope the fixture secret lives in.
func (f fixture) grant(t *testing.T, user uuid.UUID, role string) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO memberships(id,org_id,user_id,scope,role) VALUES($1,$2,$3,$4,$5)`,
		mustID(t), f.org, user, tenancy.Org(f.org).String(), role); err != nil {
		t.Fatal("insert membership")
	}
}

// gateFixture is an open approval, an installed workspace, a gate card for it
// and a Mesh user linked to a Keep admin other than the requester.
type gateFixture struct {
	fixture
	svc      *meshgate.Service
	pg       *meshgate.PG
	cards    *stubCards
	logs     *bytes.Buffer
	ws       uuid.UUID
	approval Approval
	task     uuid.UUID
	meshUser uuid.UUID
	keepUser uuid.UUID // the admin meshUser is linked to
	now      time.Time
}

func newGateFixture(t *testing.T, initiatorRef string) *gateFixture {
	t.Helper()
	f := newFixture(t)
	_, _, a := f.pending(t)
	g := &gateFixture{fixture: f, cards: &stubCards{}, logs: &bytes.Buffer{}, ws: uuid.New(), approval: a, meshUser: uuid.New(), now: time.Now()}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES($1,$2,'https://mesh.example.invalid',$3)`, g.ws, f.org, f.user); err != nil {
		t.Fatal("insert installation")
	}
	g.pg = meshgate.NewPG(f.pool)
	g.keepUser = f.approver(t)
	f.grant(t, g.keepUser, "admin")
	if err := g.pg.Link(f.ctx, g.ws, g.meshUser, f.org, g.keepUser); err != nil {
		t.Fatal("link user")
	}
	log := obs.New(g.logs)
	g.svc = meshgate.New(g.pg, GateApprovals{Src: f.repo}, g.cards, log).WithApprovers(roleApprovers{ir: identity.NewRepo(f.pool)}).
		WithClock(func() time.Time { return g.now })
	task, err := g.svc.Open(f.ctx, meshgate.OpenInput{Org: f.org, Workspace: g.ws, Approval: a.ID, InitiatorRef: initiatorRef})
	if err != nil {
		t.Fatal("open gate card")
	}
	g.task = task
	return g
}

func (g *gateFixture) event(decision, by, byType, hash string) meshgate.Decided {
	return meshgate.Decided{TaskID: g.task.String(), Decision: decision, DecidedBy: by, DecidedByType: byType, ExternalHash: hash}
}

func (g *gateFixture) handle(t *testing.T, id string, d meshgate.Decided) meshgate.Outcome {
	t.Helper()
	out, err := g.svc.Handle(g.ctx, g.org, g.ws, d, id)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	return out
}

func (g *gateFixture) status(t *testing.T) string {
	t.Helper()
	a, err := g.repo.GetApproval(g.ctx, g.org, g.approval.ID)
	if err != nil {
		t.Fatal("read approval")
	}
	return a.Status
}

func (g *gateFixture) jobs(t *testing.T) int {
	t.Helper()
	return g.count(t, `SELECT count(*) FROM deployment_jobs WHERE org_id=$1`, g.org)
}

func TestGateCardCarriesPointerNotValue(t *testing.T) {
	g := newGateFixture(t, "")
	if len(g.cards.specs) != 1 {
		t.Fatalf("cards created = %d, want 1", len(g.cards.specs))
	}
	sp := g.cards.specs[0]
	if sp.RequestHash != g.approval.BindingHash || sp.ExternalRef != "keep:approval/"+g.approval.ID.String() || !sp.Deadline.Equal(g.approval.ExpiresAt) {
		t.Fatal("card is not bound to the request hash, ref and deadline")
	}
	if !strings.Contains(sp.Body, "DB_PASSWORD") || !strings.Contains(sp.Title, "DB_PASSWORD") {
		t.Fatal("card does not name the secret")
	}
	// Opening twice yields the same card, not a second one.
	again, err := g.svc.Open(g.ctx, meshgate.OpenInput{Org: g.org, Workspace: g.ws, Approval: g.approval.ID})
	if err != nil || again != g.task || len(g.cards.specs) != 1 {
		t.Fatal("second open created another card")
	}
}

// TestGateLeakDecisionTextNeverStored: a person may paste a value into the
// answer. The text must reach neither a log, the journal, the gate row, the
// outcome nor the card.
func TestGateLeakDecisionTextNeverStored(t *testing.T) {
	g := newGateFixture(t, "")
	c := canary.New()
	if !c.In("x "+c.Value(1)) || !c.In(hex.EncodeToString([]byte(c.Value(1)))) {
		t.Fatal("canary detector is blind")
	}
	text := "approve " + c.Value(1)
	// A refused answer and an applied one both carry the text.
	g.handle(t, "e-1", g.event(text, uuid.NewString(), "agent", g.approval.BindingHash))
	out := g.handle(t, "e-2", g.event(text, g.meshUser.String(), "user", g.approval.BindingHash))
	if out.Kind != meshgate.Approved {
		t.Fatalf("outcome = %+v, want approved", out)
	}
	if g.logs.Len() == 0 {
		t.Fatal("logger saw nothing; the test proves nothing")
	}
	surfaces := map[string]string{
		"logs":    g.logs.String(),
		"outcome": fmt.Sprintf("%+v %#v", out, out),
		"cards":   fmt.Sprintf("%+v", g.cards.specs),
	}
	for _, q := range []string{
		`SELECT coalesce(string_agg(t::text, E'\n'), '') FROM audit_records t`,
		`SELECT coalesce(string_agg(t::text, E'\n'), '') FROM mesh_gate_requests t`,
		`SELECT coalesce(string_agg(t::text, E'\n'), '') FROM approval_requests t`,
	} {
		var dump string
		if err := g.pool.QueryRow(g.ctx, q).Scan(&dump); err != nil || dump == "" {
			t.Fatalf("dump %q: %v", q, err)
		}
		surfaces[q] = dump
	}
	for name, s := range surfaces {
		if c.In(s) {
			t.Fatalf("decision text leaked into %s", name)
		}
	}
}

func TestGateRefusesWhatInvariantsForbid(t *testing.T) {
	g := newGateFixture(t, "")
	h := g.approval.BindingHash
	other := hex.EncodeToString(bytes.Repeat([]byte{7}, 32))
	cases := []struct {
		name string
		ev   meshgate.Decided
		want meshgate.Reason
	}{
		{"agent decision", g.event("approve", g.meshUser.String(), "agent", h), meshgate.ReasonNotUser},
		{"system decision", g.event("approve", g.meshUser.String(), "system", h), meshgate.ReasonNotUser},
		{"hash mismatch", g.event("approve", g.meshUser.String(), "user", other), meshgate.ReasonHashMismatch},
		{"empty hash", g.event("approve", g.meshUser.String(), "user", ""), meshgate.ReasonHashMismatch},
		{"unlinked user", g.event("approve", uuid.NewString(), "user", h), meshgate.ReasonUnlinkedUser},
		{"unclear answer", g.event("maybe later", g.meshUser.String(), "user", h), meshgate.ReasonNoDecision},
		{"another card", meshgate.Decided{TaskID: uuid.NewString(), Decision: "approve", DecidedBy: g.meshUser.String(), DecidedByType: "user", ExternalHash: h}, meshgate.ReasonUnknownGate},
		{"not an id", g.event("approve", "mallory", "user", h), meshgate.ReasonMalformed},
	}
	for i, c := range cases {
		out := g.handle(t, fmt.Sprintf("e-%d", i), c.ev)
		if out.Kind != meshgate.Refused || out.Reason != c.want {
			t.Fatalf("%s: outcome = %+v, want refused/%s", c.name, out, c.want)
		}
		if g.status(t) != "requested" || g.jobs(t) != 0 {
			t.Fatalf("%s: a refused answer changed the request", c.name)
		}
	}
	// The reason of a refusal reaches the server log under keys obs forwards.
	if !strings.Contains(g.logs.String(), `"kind":"not_user"`) || strings.Contains(g.logs.String(), "dropped disallowed") {
		t.Fatalf("refusal reasons are not in the log or keys were dropped: %s", g.logs.String())
	}
	// After all of that the right answer still works: the card stayed open.
	if out := g.handle(t, "e-ok", g.event("approve", g.meshUser.String(), "user", h)); out.Kind != meshgate.Approved || g.jobs(t) != 1 {
		t.Fatalf("legitimate answer after refusals: %+v", out)
	}
}

func TestGateRefusesInitiator(t *testing.T) {
	t.Run("initiator ref", func(t *testing.T) {
		ref := uuid.New()
		g := newGateFixture(t, ref.String())
		if err := g.pg.Link(g.ctx, g.ws, ref, g.org, g.approver(t)); err != nil {
			t.Fatal("link initiator")
		}
		out := g.handle(t, "e-1", g.event("approve", ref.String(), "user", g.approval.BindingHash))
		if out.Kind != meshgate.Refused || out.Reason != meshgate.ReasonInitiator || g.status(t) != "requested" {
			t.Fatalf("initiator decided: %+v", out)
		}
	})
	t.Run("requester through a link", func(t *testing.T) {
		g := newGateFixture(t, "")
		self := uuid.New()
		// An admin, so the refusal is for asking, not for the role.
		g.grant(t, g.user, "admin")
		if err := g.pg.Link(g.ctx, g.ws, self, g.org, g.user); err != nil {
			t.Fatal("link requester")
		}
		out := g.handle(t, "e-1", g.event("approve", self.String(), "user", g.approval.BindingHash))
		if out.Kind != meshgate.Refused || out.Reason != meshgate.ReasonInitiator || g.status(t) != "requested" || g.jobs(t) != 0 {
			t.Fatalf("requester approved their own request: %+v", out)
		}
	})
}

func TestGateRepeatedEventIsIdempotent(t *testing.T) {
	g := newGateFixture(t, "")
	ev := g.event("approve: ok", g.meshUser.String(), "user", g.approval.BindingHash)
	if out := g.handle(t, "e-1", ev); out.Kind != meshgate.Approved {
		t.Fatalf("first = %+v", out)
	}
	audits := g.count(t, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='approval.decided'`, g.org.String())
	for _, id := range []string{"e-1", "e-2"} {
		if out := g.handle(t, id, ev); out.Kind != meshgate.Duplicate {
			t.Fatalf("repeat %s = %+v, want duplicate", id, out)
		}
	}
	// A later contradicting answer changes nothing either.
	if out := g.handle(t, "e-3", g.event("reject", g.meshUser.String(), "user", g.approval.BindingHash)); out.Kind != meshgate.Duplicate {
		t.Fatalf("contradicting answer = %+v", out)
	}
	if g.jobs(t) != 1 || g.status(t) != "approved" ||
		g.count(t, `SELECT count(*) FROM audit_records WHERE org_id=$1 AND action='approval.decided'`, g.org.String()) != audits {
		t.Fatal("a repeat had an effect")
	}
}

func TestGateConcurrentAnswersApplyOnce(t *testing.T) {
	g := newGateFixture(t, "")
	// More answers than the gate store has connections: the holder of the gate
	// lock still needs one for its own queries, so this is red on a store that
	// lets waiting answers take the whole pool, whatever the machine's CPUs.
	cfg := g.pool.Config().Copy()
	cfg.MaxConns = 2
	small, err := pgxpool.NewWithConfig(g.ctx, cfg)
	if err != nil {
		t.Fatal("open small pool")
	}
	t.Cleanup(small.Close)
	svc := meshgate.New(meshgate.NewPG(small), GateApprovals{Src: g.repo}, g.cards, nil).WithApprovers(roleApprovers{ir: identity.NewRepo(g.pool)}).
		WithClock(func() time.Time { return g.now })
	ev := g.event("approve", g.meshUser.String(), "user", g.approval.BindingHash)
	var wg sync.WaitGroup
	kinds := make([]meshgate.Kind, 6)
	for i := range kinds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A bounded answer: a store that hangs fails here, not at the
			// process timeout.
			ctx, cancel := context.WithTimeout(g.ctx, 20*time.Second)
			defer cancel()
			out, err := svc.Handle(ctx, g.org, g.ws, ev, fmt.Sprintf("c-%d", i))
			if err == nil {
				kinds[i] = out.Kind
			} else {
				kinds[i] = meshgate.Kind("error")
			}
		}()
	}
	wg.Wait()
	approved := 0
	for _, k := range kinds {
		if k == meshgate.Approved {
			approved++
		}
	}
	for _, k := range kinds {
		// A loser must see a repeat, not a failure that a database constraint absorbed.
		if k != meshgate.Approved && k != meshgate.Duplicate {
			t.Fatalf("a concurrent answer ended as %q (%v)", k, kinds)
		}
	}
	if approved != 1 || g.jobs(t) != 1 {
		t.Fatalf("approved=%d jobs=%d, want 1 and 1 (%v)", approved, g.jobs(t), kinds)
	}
}

func TestGateStoreRefusesAOneConnectionPool(t *testing.T) {
	g := newGateFixture(t, "")
	cfg := g.pool.Config().Copy()
	cfg.MaxConns = 1
	one, err := pgxpool.NewWithConfig(g.ctx, cfg)
	if err != nil {
		t.Fatal("open one-connection pool")
	}
	t.Cleanup(one.Close)
	// The holder of the gate lock needs a second connection: on one it would
	// wait forever, so the store refuses before it locks anything.
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	defer cancel()
	ran := false
	err = meshgate.NewPG(one).Settle(ctx, g.ws, g.task, func(meshgate.Gate) (meshgate.Settlement, error) {
		ran = true
		return meshgate.Settlement{}, nil
	})
	if !errors.Is(err, meshgate.ErrPoolTooSmall) || ran {
		t.Fatalf("settle on a one-connection pool: err=%v ran=%v, want ErrPoolTooSmall before the lock", err, ran)
	}
}

func TestGateRejectCreatesNoJob(t *testing.T) {
	g := newGateFixture(t, "")
	out := g.handle(t, "e-1", g.event("Rejected - too risky", g.meshUser.String(), "user", g.approval.BindingHash))
	if out.Kind != meshgate.Rejected || g.status(t) != "rejected" || g.jobs(t) != 0 {
		t.Fatalf("reject: %+v status=%s jobs=%d", out, g.status(t), g.jobs(t))
	}
}

func TestGateTimeoutCancelsCardAndRequest(t *testing.T) {
	g := newGateFixture(t, "")
	if n, err := g.svc.Sweep(g.ctx); err != nil || n != 0 || len(g.cards.cancelled) != 0 {
		t.Fatalf("sweep before the deadline cancelled something: n=%d err=%v", n, err)
	}
	g.now = g.approval.ExpiresAt.Add(time.Minute)
	// A late answer is refused and the approval is not approved.
	late := g.event("approve", g.meshUser.String(), "user", g.approval.BindingHash)
	if out := g.handle(t, "e-late", late); out.Kind != meshgate.Refused || out.Reason != meshgate.ReasonExpired {
		t.Fatalf("late answer = %+v", out)
	}
	g.cards.cancelErr = gatecard.ErrRefused
	if n, _ := g.svc.Sweep(g.ctx); n != 0 {
		t.Fatal("a card Mesh refused to close counted as cancelled")
	}
	g.cards.cancelErr = nil
	if n, err := g.svc.Sweep(g.ctx); err != nil || n != 1 || len(g.cards.cancelled) != 1 || g.cards.cancelled[0] != g.task.String() {
		t.Fatalf("sweep: n=%d err=%v cancelled=%v", n, err, g.cards.cancelled)
	}
	if n, _ := g.svc.Sweep(g.ctx); n != 0 || len(g.cards.cancelled) != 1 {
		t.Fatal("a cancelled card was cancelled again")
	}
	g.now = time.Now() // even a clock that went back cannot revive it
	if out := g.handle(t, "e-after", late); out.Kind != meshgate.Duplicate {
		t.Fatalf("answer after the sweep = %+v, want duplicate", out)
	}
	var st string
	if err := g.pool.QueryRow(g.ctx, `SELECT status FROM mesh_gate_requests WHERE task_id=$1`, g.task).Scan(&st); err != nil || st != "expired" || g.jobs(t) != 0 {
		t.Fatalf("gate status=%q jobs=%d", st, g.jobs(t))
	}
}

func TestGateOpenRefusesLapsedApproval(t *testing.T) {
	f := newFixture(t)
	_, _, a := f.pending(t)
	svc := meshgate.New(meshgate.NewPG(f.pool), GateApprovals{Src: f.repo}, &stubCards{}, nil).
		WithClock(func() time.Time { return a.ExpiresAt.Add(time.Second) })
	if _, err := svc.Open(f.ctx, meshgate.OpenInput{Org: f.org, Workspace: uuid.New(), Approval: a.ID}); !errors.Is(err, meshgate.ErrExpired) {
		t.Fatalf("open on a lapsed approval = %v, want ErrExpired", err)
	}
}

// Decide commits in its own transaction. An approval decided elsewhere (the
// console, or an earlier delivery whose gate update failed) must bring the gate
// in line, so the sweep never cancels the card of a decided request.
func TestGateDecidedElsewhereSettlesGateNotExpired(t *testing.T) {
	g := newGateFixture(t, "")
	if _, err := g.repo.Decide(g.ctx, DecideInput{OrgID: g.org, ApprovalID: g.approval.ID, ApproverID: g.approver(t), ApproverIsUser: true,
		Approve: true, BindingHash: g.approval.BindingHash, Reason: "console"}); err != nil {
		t.Fatalf("decide in console: %v", err)
	}
	if out := g.handle(t, "e-late-gate", g.event("approve", g.meshUser.String(), "user", g.approval.BindingHash)); out.Kind != meshgate.Duplicate {
		t.Fatalf("answer to a decided request = %+v, want duplicate", out)
	}
	var st string
	if err := g.pool.QueryRow(g.ctx, `SELECT status FROM mesh_gate_requests WHERE task_id=$1`, g.task).Scan(&st); err != nil || st != "approved" {
		t.Fatalf("gate status = %q (%v), want approved", st, err)
	}
	g.now = g.approval.ExpiresAt.Add(time.Minute)
	if n, _ := g.svc.Sweep(g.ctx); n != 0 || len(g.cards.cancelled) != 0 {
		t.Fatal("the sweep cancelled the card of an approved request")
	}
}

// A link names who answered; only a role that may approve in the secret's
// scope decides, and a link to a removed user names nobody.
func TestGateDecidesOnlyByRole(t *testing.T) {
	g := newGateFixture(t, "")
	h := g.approval.BindingHash
	link := func(role string) uuid.UUID {
		t.Helper()
		m, u := uuid.New(), g.approver(t)
		if role != "" {
			g.grant(t, u, role)
		}
		if err := g.pg.Link(g.ctx, g.ws, m, g.org, u); err != nil {
			t.Fatal("link user")
		}
		return m
	}
	cases := []struct {
		name string
		by   uuid.UUID
		want meshgate.Reason
	}{
		{"unlinked", uuid.New(), meshgate.ReasonUnlinkedUser},
		{"linked, no role", link(""), meshgate.ReasonNotApprover},
		{"linked viewer", link("viewer"), meshgate.ReasonNotApprover},
		{"linked member", link("member"), meshgate.ReasonNotApprover},
	}
	for i, c := range cases {
		out := g.handle(t, fmt.Sprintf("r-%d", i), g.event("approve", c.by.String(), "user", h))
		if out.Kind != meshgate.Refused || out.Reason != c.want {
			t.Fatalf("%s: outcome = %+v, want refused/%s", c.name, out, c.want)
		}
		if g.status(t) != "requested" || g.jobs(t) != 0 {
			t.Fatalf("%s: a refused answer changed the request", c.name)
		}
	}
	// An admin of another scope is not an admin of this one.
	elsewhere := g.approver(t)
	if _, err := g.pool.Exec(g.ctx, `INSERT INTO memberships(id,org_id,user_id,scope,role) VALUES($1,$2,$3,$4,'admin')`,
		mustID(t), g.org, elsewhere, tenancy.Scope{Level: tenancy.LevelWorkspace, ID: uuid.New()}.String()); err != nil {
		t.Fatal("insert membership")
	}
	other := uuid.New()
	if err := g.pg.Link(g.ctx, g.ws, other, g.org, elsewhere); err != nil {
		t.Fatal("link user")
	}
	if out := g.handle(t, "r-elsewhere", g.event("approve", other.String(), "user", h)); out.Kind != meshgate.Refused || out.Reason != meshgate.ReasonNotApprover {
		t.Fatalf("admin of another scope: %+v", out)
	}
	// The linked admin, once removed, names nobody.
	if _, err := g.pool.Exec(g.ctx, `UPDATE users SET status='removed', removed_at=now() WHERE org_id=$1 AND id=$2`, g.org, g.keepUser); err != nil {
		t.Fatal("remove user")
	}
	if out := g.handle(t, "r-removed", g.event("approve", g.meshUser.String(), "user", h)); out.Kind != meshgate.Refused || out.Reason != meshgate.ReasonUnlinkedUser {
		t.Fatalf("removed user: %+v", out)
	}
	if g.status(t) != "requested" || g.jobs(t) != 0 {
		t.Fatal("a refused answer changed the request")
	}
	// A linked admin decides: the card stayed open through every refusal.
	if out := g.handle(t, "r-admin", g.event("approve", link("admin").String(), "user", h)); out.Kind != meshgate.Approved || g.jobs(t) != 1 {
		t.Fatalf("linked admin: %+v", out)
	}
}

// Without a role check, or when it fails, the gate decides nothing.
func TestGateWithoutRoleCheckDecidesNothing(t *testing.T) {
	g := newGateFixture(t, "")
	ev := g.event("approve", g.meshUser.String(), "user", g.approval.BindingHash)
	for name, svc := range map[string]*meshgate.Service{
		"unset":  meshgate.New(g.pg, GateApprovals{Src: g.repo}, g.cards, nil),
		"failed": meshgate.New(g.pg, GateApprovals{Src: g.repo}, g.cards, nil).WithApprovers(failingApprovers{}),
	} {
		if _, err := svc.Handle(g.ctx, g.org, g.ws, ev, "u-"+name); !errors.Is(err, meshgate.ErrUnavailable) {
			t.Fatalf("%s role check: err = %v, want ErrUnavailable", name, err)
		}
	}
	if g.status(t) != "requested" || g.jobs(t) != 0 {
		t.Fatal("an answer without a role check changed the request")
	}
}

type failingApprovers struct{}

func (failingApprovers) CanApprove(context.Context, uuid.UUID, uuid.UUID, tenancy.Scope) (bool, error) {
	return true, errors.New("role lookup failed")
}

// A link counts only inside the organization it was made for.
func TestGateLinkIsBoundToOrg(t *testing.T) {
	g := newGateFixture(t, "")
	if _, ok, err := g.pg.LinkedUser(g.ctx, g.org, g.ws, g.meshUser); err != nil || !ok {
		t.Fatalf("linked user not found in its own org: ok=%v err=%v", ok, err)
	}
	if _, ok, err := g.pg.LinkedUser(g.ctx, uuid.New(), g.ws, g.meshUser); err != nil || ok {
		t.Fatalf("link visible from another org: ok=%v err=%v", ok, err)
	}
}

// flakyStore fails the one call a test names and passes the rest to the real store.
type flakyStore struct {
	*meshgate.PG
	failInsert, failMark bool
}

func (s flakyStore) Insert(ctx context.Context, g meshgate.Gate) error {
	if s.failInsert {
		return errors.New("insert failed")
	}
	return s.PG.Insert(ctx, g)
}

func (s flakyStore) CardCancelled(ctx context.Context, ws, task uuid.UUID) error {
	if s.failMark {
		return errors.New("mark failed")
	}
	return s.PG.CardCancelled(ctx, ws, task)
}

// A card Keep cannot account for is closed, not left to be answered.
func TestGateOpenCancelsCardItCannotRegister(t *testing.T) {
	f := newFixture(t)
	_, _, a := f.pending(t)
	cards := &stubCards{}
	svc := meshgate.New(flakyStore{PG: meshgate.NewPG(f.pool), failInsert: true}, GateApprovals{Src: f.repo}, cards, nil)
	if _, err := svc.Open(f.ctx, meshgate.OpenInput{Org: f.org, Workspace: uuid.New(), Approval: a.ID}); !errors.Is(err, meshgate.ErrUnavailable) {
		t.Fatalf("Open = %v, want ErrUnavailable", err)
	}
	if len(cards.specs) != 1 || len(cards.cancelled) != 1 {
		t.Fatalf("created %d, cancelled %d; want the orphan card cancelled", len(cards.specs), len(cards.cancelled))
	}
}

// A card whose cancel could not be recorded is not counted as cancelled.
func TestGateSweepDoesNotCountUnrecordedCancel(t *testing.T) {
	g := newGateFixture(t, "")
	g.now = g.approval.ExpiresAt.Add(time.Minute)
	svc := meshgate.New(flakyStore{PG: g.pg, failMark: true}, GateApprovals{Src: g.repo}, g.cards, nil).WithClock(func() time.Time { return g.now })
	if n, err := svc.Sweep(g.ctx); err != nil || n != 0 {
		t.Fatalf("sweep with an unrecorded cancel: n=%d err=%v, want 0", n, err)
	}
}

// A gate answers only to the organization and workspace it belongs to.
func TestGateIsBoundToOrgAndWorkspace(t *testing.T) {
	g := newGateFixture(t, "")
	ev := g.event("approve", g.meshUser.String(), "user", g.approval.BindingHash)
	if out, err := g.svc.Handle(g.ctx, uuid.New(), g.ws, ev, "other-org"); err != nil || out.Kind != meshgate.Refused || out.Reason != meshgate.ReasonUnknownGate {
		t.Fatalf("answer from another org = %+v, %v", out, err)
	}
	if out, err := g.svc.Handle(g.ctx, g.org, uuid.New(), ev, "other-ws"); err != nil || out.Kind != meshgate.Refused || out.Reason != meshgate.ReasonUnknownGate {
		t.Fatalf("answer from another workspace = %+v, %v", out, err)
	}
	if _, ok, err := g.pg.LinkedUser(g.ctx, g.org, uuid.New(), g.meshUser); err != nil || ok {
		t.Fatalf("link visible from another workspace: ok=%v err=%v", ok, err)
	}
	if g.status(t) != "requested" || g.jobs(t) != 0 {
		t.Fatal("a refused answer changed the request")
	}
}

// The card text is a closed list of lines: names, classes and ids, nothing more.
func TestGateCardBodyIsClosedSet(t *testing.T) {
	g := newGateFixture(t, "")
	lines := strings.Split(g.cards.specs[0].Body, "\n")
	prefixes := []string{"Secret: ", "Class: ", "Asked: ", "Request: ", "Approval: ", "Request hash: ", "Answer with the word"}
	if len(lines) != len(prefixes) {
		t.Fatalf("card body has %d lines, want %d: %q", len(lines), len(prefixes), lines)
	}
	for i, l := range lines {
		if !strings.HasPrefix(l, prefixes[i]) {
			t.Fatalf("card body line %d = %q, want prefix %q", i, l, prefixes[i])
		}
	}
}
