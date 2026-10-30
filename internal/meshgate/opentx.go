package meshgate

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Request is an approval that is about to be committed: everything the card
// shows, taken from the caller because the row is not visible to anyone else
// yet.
type Request struct {
	Org, Approval uuid.UUID
	Kind          string // deploy, exec or rotate
	SecretName    string
	Class         string
	RequestID     string
	BindingHash   [32]byte
	ExpiresAt     time.Time
}

// TxStore is the part of a Store that works inside the transaction creating
// the approval.
type TxStore interface {
	// WorkspacesOfTx lists the Mesh workspaces installed for org as an
	// extension: a store-only workspace has no Keep extension to answer a card.
	WorkspacesOfTx(ctx context.Context, tx pgx.Tx, org uuid.UUID) ([]uuid.UUID, error)
	InsertTx(ctx context.Context, tx pgx.Tx, g Gate) error
}

// OpenTx creates the gate card of an approval inside tx, the transaction that
// inserts the approval itself, and records the gate in the same tx. The caller
// commits. An error means no card is left to answer: the caller rolls back and
// no approval exists. The returned undo closes the card when the commit itself
// then fails.
func (s *Service) OpenTx(ctx context.Context, tx pgx.Tx, r Request) (undo func(context.Context), err error) {
	ts, ok := s.store.(TxStore)
	if s.cards == nil || !ok {
		return nil, ErrUnavailable
	}
	ws, err := ts.WorkspacesOfTx(ctx, tx, r.Org)
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(ws) != 1 {
		// With the gate configured every new approval gets a card. No
		// installation leaves nobody to ask, and several leave Keep guessing
		// which workspace to ask: either way no approval is made.
		return nil, ErrUnavailable
	}
	a := Approval{ID: r.Approval, Status: "requested", BindingHash: hex.EncodeToString(r.BindingHash[:]), ExpiresAt: r.ExpiresAt,
		SecretName: r.SecretName, Class: r.Class, Kind: r.Kind, RequestID: r.RequestID}
	id, err := s.cards.Create(ctx, gatecard.Spec{
		Title:       "Keep: confirm " + a.Kind + " of " + a.SecretName,
		Body:        spec(a),
		ExternalRef: "keep:approval/" + a.ID.String(),
		RequestHash: a.BindingHash,
		Deadline:    a.ExpiresAt,
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	cancel := func(c context.Context) {
		_ = s.cards.Cancel(context.WithoutCancel(c), id, "request not registered")
	}
	task, perr := uuid.Parse(id)
	g := Gate{Workspace: ws[0], TaskID: task, Org: r.Org, Approval: r.Approval, Hash: r.BindingHash, Status: "pending", ExpiresAt: r.ExpiresAt}
	if perr != nil || ts.InsertTx(ctx, tx, g) != nil {
		// A card Keep cannot account for is closed, not left to be answered.
		cancel(ctx)
		return nil, ErrUnavailable
	}
	return cancel, nil
}
