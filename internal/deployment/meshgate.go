package deployment

import (
	"context"
	"errors"
	"time"

	"github.com/entire-vc/evc-keep/internal/meshgate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GateSource is the approval store a Mesh gate decides through: this package's
// Repo, or the merged view that also holds rotation approvals.
type GateSource interface {
	GetApproval(ctx context.Context, org, id uuid.UUID) (Approval, error)
	Decide(ctx context.Context, in DecideInput) (DecideResult, error)
}

// GateApprovals adapts a GateSource to meshgate.Approvals, mapping this
// package's refusals onto the gate's closed set.
type GateApprovals struct{ Src GateSource }

var _ meshgate.Approvals = GateApprovals{}

// Get implements meshgate.Approvals.
func (g GateApprovals) Get(ctx context.Context, org, id uuid.UUID) (meshgate.Approval, error) {
	a, err := g.Src.GetApproval(ctx, org, id)
	if err != nil {
		return meshgate.Approval{}, gateErr(err)
	}
	kind := "deploy"
	switch {
	case a.Rotate:
		kind = "rotate"
	case a.Exec != nil:
		kind = "exec"
	}
	return meshgate.Approval{ID: a.ID, Status: a.Status, BindingHash: a.BindingHash, RequesterID: a.Requester.ID,
		ExpiresAt: a.ExpiresAt, SecretName: a.SecretName, Class: a.SecretClass, Kind: kind, RequestID: a.RequestID, Scope: a.Scope}, nil
}

// Decide implements meshgate.Approvals. The reason is fixed: what a person
// wrote in Mesh is never carried into Keep's journal.
func (g GateApprovals) Decide(ctx context.Context, org, id, approver uuid.UUID, approve bool, hash string) error {
	reason := "decided through a Mesh gate card"
	if !approve {
		reason = "rejected through a Mesh gate card"
	}
	_, err := g.Src.Decide(ctx, DecideInput{OrgID: org, ApprovalID: id, ApproverID: approver, ApproverIsUser: true,
		Approve: approve, Reason: reason, BindingHash: hash})
	return gateErr(err)
}

func gateErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return meshgate.ErrNotFound
	case errors.Is(err, ErrAlreadyDecided):
		return meshgate.ErrAlreadyDecided
	case errors.Is(err, ErrExpired):
		return meshgate.ErrExpired
	case errors.Is(err, ErrBindingMismatch):
		return meshgate.ErrBinding
	case errors.Is(err, ErrSelfApproval):
		return meshgate.ErrSelf
	case errors.Is(err, ErrNotHuman):
		return meshgate.ErrNotHuman
	case errors.Is(err, ErrRefused):
		return meshgate.ErrNotExecutable
	}
	return meshgate.ErrUnavailable
}

// Confirmation is a new approval, as it is about to be shown to a person.
type Confirmation struct {
	OrgID, ApprovalID uuid.UUID
	Kind              string // deploy, exec or rotate
	SecretName        string
	SecretClass       string
	RequestID         string
	BindingHash       [32]byte
	ExpiresAt         time.Time
}

// Confirmer asks a person to confirm a new approval, inside the transaction
// that inserts it. An error fails the request: the caller rolls the
// transaction back, so no approval is left without its card. A non-nil undo
// takes the card back when the commit then fails.
type Confirmer interface {
	Confirm(ctx context.Context, tx pgx.Tx, c Confirmation) (undo func(context.Context), err error)
}

// GateConfirmer is the Confirmer backed by the Mesh gate.
type GateConfirmer struct{ Svc *meshgate.Service }

var _ Confirmer = GateConfirmer{}

// Confirm implements Confirmer. Every failure is ErrUnavailable: the reason
// belongs to the tracker and is not forwarded.
func (g GateConfirmer) Confirm(ctx context.Context, tx pgx.Tx, c Confirmation) (func(context.Context), error) {
	if g.Svc == nil {
		return nil, ErrUnavailable
	}
	undo, err := g.Svc.OpenTx(ctx, tx, meshgate.Request{Org: c.OrgID, Approval: c.ApprovalID, Kind: c.Kind, SecretName: c.SecretName,
		Class: c.SecretClass, RequestID: c.RequestID, BindingHash: c.BindingHash, ExpiresAt: c.ExpiresAt})
	if err != nil {
		return nil, ErrUnavailable
	}
	return undo, nil
}
