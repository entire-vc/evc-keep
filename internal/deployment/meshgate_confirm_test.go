package deployment

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// failingCards is a Mesh that refuses to make a card.
type failingCards struct{ *stubCards }

func (*failingCards) Create(context.Context, gatecard.Spec) (string, error) {
	return "", gatecard.ErrUnavailable
}

// insertFails is a gate table that refuses the row of a card Mesh made.
type insertFails struct{ *meshgate.PG }

func (insertFails) InsertTx(context.Context, pgx.Tx, meshgate.Gate) error {
	return errors.New("insert failed")
}

// rows counts everything one approval request leaves behind.
type rows struct{ requests, approvals, gates, journal int }

func (f fixture) rows(t *testing.T) rows {
	t.Helper()
	return rows{
		requests:  f.count(t, `SELECT count(*) FROM deployment_requests WHERE org_id=$1`, f.org),
		approvals: f.count(t, `SELECT count(*) FROM approval_requests WHERE org_id=$1`, f.org),
		gates:     f.count(t, `SELECT count(*) FROM mesh_gate_requests WHERE org_id=$1`, f.org),
		journal:   f.count(t, `SELECT count(*) FROM audit_records WHERE org_id=$1`, f.org.String()),
	}
}

func (f fixture) install(t *testing.T) uuid.UUID {
	t.Helper()
	ws := uuid.New()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES($1,$2,'https://mesh.example.invalid',$3)`, ws, f.org, f.user); err != nil {
		t.Fatal("insert installation")
	}
	return ws
}

func (f fixture) gated(store meshgate.Store, cards gatecard.Cards) {
	svc := meshgate.New(store, GateApprovals{Src: f.repo}, cards, nil)
	f.repo.WithConfirmer(GateConfirmer{Svc: svc})
}

// A new approval gets its card in the same transaction: card, gate row and
// approval agree, and the card is bound to the approval's own hash and expiry.
func TestConfirmerCreatesTheCardWithTheApproval(t *testing.T) {
	f := newFixture(t)
	ws := f.install(t)
	cards := &stubCards{}
	f.gated(meshgate.NewPG(f.pool), cards)
	out, err := f.repo.Submit(f.ctx, f.request(t))
	if err != nil || out.Status != NeedsApproval {
		t.Fatalf("Submit = %v, %v", out.Status, err)
	}
	a, err := f.repo.GetApproval(f.ctx, f.org, out.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards.specs) != 1 {
		t.Fatalf("cards = %d, want 1", len(cards.specs))
	}
	sp := cards.specs[0]
	if sp.RequestHash != a.BindingHash || sp.ExternalRef != "keep:approval/"+a.ID.String() || !sp.Deadline.Equal(a.ExpiresAt) ||
		!strings.Contains(sp.Title, "deploy") || !strings.Contains(sp.Body, "DB_PASSWORD") {
		t.Fatalf("card does not describe the approval: %+v", sp)
	}
	g, ok, err := meshgate.NewPG(f.pool).ByApproval(f.ctx, f.org, a.ID)
	if err != nil || !ok || g.Workspace != ws || g.Status != "pending" {
		t.Fatalf("gate row = %+v, %v, %v", g, ok, err)
	}
	// The same request again returns the first outcome and asks nobody twice.
	if _, err = f.repo.Submit(f.ctx, requestOf(t, f, out)); err != nil {
		t.Fatal(err)
	}
	if len(cards.specs) != 1 {
		t.Fatalf("a repeated request made %d cards", len(cards.specs))
	}
}

func requestOf(t *testing.T, f fixture, out Outcome) Request {
	t.Helper()
	var rid string
	if err := f.pool.QueryRow(f.ctx, `SELECT request_id FROM deployment_requests WHERE org_id=$1 AND id=$2`, f.org, out.ID).Scan(&rid); err != nil {
		t.Fatal(err)
	}
	in := f.request(t)
	in.RequestID = rid
	return in
}

// A card that cannot be made fails the request with the unavailable class and
// leaves no row behind: no request, no approval, no gate, no journal record.
func TestConfirmerRefusalLeavesNoApproval(t *testing.T) {
	for name, tc := range map[string]struct {
		store func(f fixture) meshgate.Store
		cards func() gatecard.Cards
		want  int // cards cancelled
	}{
		"mesh refuses the card": {func(f fixture) meshgate.Store { return meshgate.NewPG(f.pool) }, func() gatecard.Cards { return &failingCards{&stubCards{}} }, 0},
		"gate row refused":      {func(f fixture) meshgate.Store { return insertFails{meshgate.NewPG(f.pool)} }, func() gatecard.Cards { return &stubCards{} }, 1},
		"no tracker at all":     {func(f fixture) meshgate.Store { return meshgate.NewPG(f.pool) }, func() gatecard.Cards { return nil }, 0},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.install(t)
			before := f.rows(t)
			cards := tc.cards()
			f.gated(tc.store(f), cards)
			out, err := f.repo.Submit(f.ctx, f.request(t))
			if !errors.Is(err, ErrUnavailable) || out.ApprovalID != uuid.Nil {
				t.Fatalf("Submit = %+v, %v; want ErrUnavailable and no approval", out, err)
			}
			if after := f.rows(t); after != before {
				t.Fatalf("rows left behind: before %+v, after %+v", before, after)
			}
			if sc, ok := cards.(*stubCards); ok && len(sc.cancelled) != tc.want {
				t.Fatalf("cancelled = %d, want %d", len(sc.cancelled), tc.want)
			}
		})
	}
}

// A commit that fails after the card exists takes the card back.
func TestConfirmerUndoesTheCardWhenTheCommitFails(t *testing.T) {
	f := newFixture(t)
	f.install(t)
	cards := &stubCards{}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	inner := GateConfirmer{Svc: meshgate.New(meshgate.NewPG(f.pool), GateApprovals{Src: f.repo}, cards, nil)}
	f.repo.WithConfirmer(confirmerFunc(func(c context.Context, tx pgx.Tx, in Confirmation) (func(context.Context), error) {
		undo, err := inner.Confirm(c, tx, in)
		cancel() // the commit that follows cannot succeed
		return undo, err
	}))
	before := f.rows(t)
	if _, err := f.repo.Submit(ctx, f.request(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Submit = %v, want ErrUnavailable", err)
	}
	if len(cards.specs) != 1 || len(cards.cancelled) != 1 {
		t.Fatalf("created %d, cancelled %d; want the card taken back", len(cards.specs), len(cards.cancelled))
	}
	if after := f.rows(t); after != before {
		t.Fatalf("rows left behind: before %+v, after %+v", before, after)
	}
}

type confirmerFunc func(context.Context, pgx.Tx, Confirmation) (func(context.Context), error)

func (c confirmerFunc) Confirm(ctx context.Context, tx pgx.Tx, in Confirmation) (func(context.Context), error) {
	return c(ctx, tx, in)
}

// With the gate configured, an organization without a Mesh installation has
// nobody to ask: the approval is refused and leaves no row, no card and no
// gate, rather than waiting for an answer that cannot come.
func TestConfirmerRefusesOrganizationsWithoutMesh(t *testing.T) {
	f := newFixture(t)
	cards := &stubCards{}
	f.gated(meshgate.NewPG(f.pool), cards)
	before := f.rows(t)
	if _, err := f.repo.Submit(f.ctx, f.request(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Submit = %v, want ErrUnavailable", err)
	}
	if len(cards.specs) != 0 || f.rows(t) != before {
		t.Fatal("an organization without Mesh produced a card or rows")
	}
}

// Two installed workspaces: which one to ask is not guessed.
func TestConfirmerRefusesAnAmbiguousWorkspace(t *testing.T) {
	f := newFixture(t)
	f.install(t)
	f.install(t)
	cards := &stubCards{}
	f.gated(meshgate.NewPG(f.pool), cards)
	before := f.rows(t)
	if _, err := f.repo.Submit(f.ctx, f.request(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Submit = %v, want ErrUnavailable", err)
	}
	if len(cards.specs) != 0 || f.rows(t) != before {
		t.Fatal("an ambiguous organization produced a card or rows")
	}
}
