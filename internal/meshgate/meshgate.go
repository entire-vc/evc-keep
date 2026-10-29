// Package meshgate confirms Keep requests through gate cards in Mesh. Keep
// asks a person by creating a card (through gatecard.Cards) and applies the
// answer that comes back as the task.gate.decided event. Keep's core does not
// depend on Mesh: the card side is the gatecard.Cards interface, and the
// approval side is Approvals.
//
// Every invariant of a human approval is checked here again, because the
// answer arrives from outside: only a person decides (decided_by_type=user),
// never the one who asked, only someone whose Keep role may approve in the
// secret's scope, only for the request whose hash the card carries, and only
// once. A Mesh link names the Keep user; it never grants the right to decide. A refused answer changes nothing and the card stays open.
//
// The free text of the decision is read for one word and dropped: it is never
// logged, stored, journaled or returned, because a person may paste anything
// into it.
package meshgate

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/google/uuid"
)

// Reason is why an answer was refused. The set is closed.
type Reason string

const (
	ReasonNotUser       Reason = "not_user"       // decided_by_type is not user
	ReasonInitiator     Reason = "initiator"      // the decider is the one who asked
	ReasonHashMismatch  Reason = "hash_mismatch"  // the answer is for another request
	ReasonUnknownGate   Reason = "unknown_gate"   // no such open card in this workspace
	ReasonUnlinkedUser  Reason = "unlinked_user"  // the Mesh user is linked to no active Keep user
	ReasonNotApprover   Reason = "not_approver"   // the Keep user may not approve in the secret's scope
	ReasonNoDecision    Reason = "no_decision"    // the text starts with neither approve nor reject
	ReasonExpired       Reason = "expired"        // the request lapsed
	ReasonNotExecutable Reason = "not_executable" // policy no longer allows what was asked
	ReasonMalformed     Reason = "malformed"      // ids that are not ids
)

// Kind is what Handle did with an answer.
type Kind string

const (
	Approved  Kind = "approved"
	Rejected  Kind = "rejected"
	Duplicate Kind = "duplicate" // the request was already decided; nothing changed
	Refused   Kind = "refused"   // see Outcome.Reason; nothing changed
)

// Outcome is the closed result of Handle: nothing from the answer's text.
type Outcome struct {
	Kind   Kind
	Reason Reason // set only when Kind is Refused
}

// Decided is the task.gate.decided event as Keep reads it. Decision is the
// recorded text of the answer; only its first word is used.
type Decided struct {
	TaskID        string
	Decision      string
	DecidedBy     string
	DecidedByType string
	ExternalHash  string
}

// Approval is the part of a stored approval the gate needs.
type Approval struct {
	ID          uuid.UUID
	Status      string // requested, approved, rejected, expired
	BindingHash string // hex
	RequesterID string
	ExpiresAt   time.Time
	SecretName  string
	Class       string
	Kind        string // what is asked: deploy, exec or rotate
	RequestID   string
	Scope       tenancy.Scope // the secret's catalog scope, where the right to approve is checked
}

// Errors an Approvals implementation maps its refusals onto.
var (
	ErrNotFound       = errors.New("meshgate: approval not found")
	ErrAlreadyDecided = errors.New("meshgate: approval already decided")
	ErrExpired        = errors.New("meshgate: approval expired")
	ErrBinding        = errors.New("meshgate: hash does not match the stored request")
	ErrSelf           = errors.New("meshgate: requester cannot decide their own request")
	ErrNotHuman       = errors.New("meshgate: decider is not a person")
	ErrNotExecutable  = errors.New("meshgate: request can no longer be executed")
	// ErrUnavailable is anything else: the caller may retry.
	ErrUnavailable = errors.New("meshgate: unavailable")
)

// Approvals is the Keep approval store the gate decides through.
type Approvals interface {
	Get(ctx context.Context, org, id uuid.UUID) (Approval, error)
	// Decide records a human decision by the Keep user approver. hash is what
	// the card carried; the store checks it against the stored request.
	Decide(ctx context.Context, org, id, approver uuid.UUID, approve bool, hash string) error
}

// Approvers says whether a Keep user may decide approvals in a scope: the same
// role check the console makes before it shows the approve button.
type Approvers interface {
	CanApprove(ctx context.Context, org, user uuid.UUID, scope tenancy.Scope) (bool, error)
}

// Gate is one open or settled card.
type Gate struct {
	Workspace    uuid.UUID
	TaskID       uuid.UUID
	Org          uuid.UUID
	Approval     uuid.UUID
	Hash         [32]byte
	InitiatorRef string
	Status       string
	ExpiresAt    time.Time
	CardCancel   bool
}

// Store persists gates. Tx runs fn with the gate row of (workspace, task)
// locked; fn returns the new status (and the deciding Mesh user) to record, or
// the empty status to leave the row as it is.
type Store interface {
	Insert(ctx context.Context, g Gate) error
	ByApproval(ctx context.Context, org, approval uuid.UUID) (Gate, bool, error)
	LinkedUser(ctx context.Context, org, workspace, meshUser uuid.UUID) (uuid.UUID, bool, error)
	Settle(ctx context.Context, workspace, task uuid.UUID, fn func(Gate) (Settlement, error)) error
	// Lapsed marks every pending gate past its deadline expired and returns
	// the gates whose card is still to be cancelled.
	Lapsed(ctx context.Context, now time.Time) ([]Gate, error)
	CardCancelled(ctx context.Context, workspace, task uuid.UUID) error
}

// Settlement is what fn of Store.Settle decided.
type Settlement struct {
	Status    string // "" leaves the row untouched
	MeshUser  uuid.UUID
	EventID   string
	DecidedAt time.Time
}

// Service is the confirmation backend.
type Service struct {
	store     Store
	approvals Approvals
	approvers Approvers
	cards     gatecard.Cards
	log       *slog.Logger
	now       func() time.Time
}

// New returns a Service. cards may be nil when the service only receives
// answers (Open and Sweep then refuse).
func New(store Store, approvals Approvals, cards gatecard.Cards, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{store: store, approvals: approvals, cards: cards, log: log, now: time.Now}
}

// WithApprovers sets the role check every answer passes. Without it Handle
// decides nothing: each answer is ErrUnavailable.
func (s *Service) WithApprovers(a Approvers) *Service {
	s.approvers = a
	return s
}

// OpenInput names the request to confirm.
type OpenInput struct {
	Org, Workspace, Approval uuid.UUID
	// InitiatorRef is the Mesh id of whoever asked, when known.
	InitiatorRef string
}

// Open creates the gate card of an open approval. The same approval opened
// twice returns the same card.
func (s *Service) Open(ctx context.Context, in OpenInput) (uuid.UUID, error) {
	if s.cards == nil {
		return uuid.Nil, ErrUnavailable
	}
	if prev, ok, err := s.store.ByApproval(ctx, in.Org, in.Approval); err != nil {
		return uuid.Nil, ErrUnavailable
	} else if ok {
		return prev.TaskID, nil
	}
	a, err := s.approvals.Get(ctx, in.Org, in.Approval)
	if err != nil {
		return uuid.Nil, err
	}
	if a.Status != "requested" || !a.ExpiresAt.After(s.now()) {
		return uuid.Nil, ErrExpired
	}
	raw, err := hex.DecodeString(a.BindingHash)
	if err != nil || len(raw) != 32 {
		return uuid.Nil, ErrBinding
	}
	id, err := s.cards.Create(ctx, gatecard.Spec{
		Title:       "Keep: confirm " + a.Kind + " of " + a.SecretName,
		Body:        spec(a),
		ExternalRef: "keep:approval/" + a.ID.String(),
		RequestHash: a.BindingHash,
		Deadline:    a.ExpiresAt,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("meshgate: create card: %w", err)
	}
	task, perr := uuid.Parse(id)
	g := Gate{Workspace: in.Workspace, TaskID: task, Org: in.Org, Approval: a.ID, InitiatorRef: in.InitiatorRef,
		Status: "pending", ExpiresAt: a.ExpiresAt}
	copy(g.Hash[:], raw)
	if perr != nil || s.store.Insert(ctx, g) != nil {
		// A card Keep cannot account for is closed, not left to be answered.
		_ = s.cards.Cancel(context.WithoutCancel(ctx), id, "request not registered")
		return uuid.Nil, ErrUnavailable
	}
	return task, nil
}

// spec is the card text: names, classes and ids, nothing else.
func spec(a Approval) string {
	return "Secret: " + a.SecretName + "\nClass: " + a.Class + "\nAsked: " + a.Kind +
		"\nRequest: " + a.RequestID + "\nApproval: " + a.ID.String() + "\nRequest hash: " + a.BindingHash +
		"\nAnswer with the word approve or reject first."
}

// Handle applies one task.gate.decided answer of workspace (owned by org).
// A refused or repeated answer changes nothing. An error means "try again":
// nothing was changed.
func (s *Service) Handle(ctx context.Context, org, workspace uuid.UUID, d Decided, eventID string) (Outcome, error) {
	refuse := func(r Reason) (Outcome, error) {
		s.log.LogAttrs(ctx, slog.LevelWarn, "mesh gate answer refused", slog.String("workspace_id", workspace.String()), slog.String("kind", string(r)))
		return Outcome{Kind: Refused, Reason: r}, nil
	}
	if d.DecidedByType != "user" {
		return refuse(ReasonNotUser)
	}
	task, terr := uuid.Parse(d.TaskID)
	by, berr := uuid.Parse(d.DecidedBy)
	if terr != nil || berr != nil {
		return refuse(ReasonMalformed)
	}
	approve, ok := parseDecision(d.Decision)
	if !ok {
		return refuse(ReasonNoDecision)
	}
	out := Outcome{}
	err := s.store.Settle(ctx, workspace, task, func(g Gate) (Settlement, error) {
		switch {
		case g.Org != org:
			out = Outcome{Kind: Refused, Reason: ReasonUnknownGate}
			return Settlement{}, nil
		case g.Status != "pending":
			out = Outcome{Kind: Duplicate}
			return Settlement{}, nil
		}
		shown, derr := hex.DecodeString(d.ExternalHash)
		if derr != nil || subtle.ConstantTimeCompare(shown, g.Hash[:]) != 1 {
			out = Outcome{Kind: Refused, Reason: ReasonHashMismatch}
			return Settlement{}, nil
		}
		if g.InitiatorRef != "" && strings.EqualFold(g.InitiatorRef, by.String()) {
			out = Outcome{Kind: Refused, Reason: ReasonInitiator}
			return Settlement{}, nil
		}
		if !s.now().Before(g.ExpiresAt) {
			out = Outcome{Kind: Refused, Reason: ReasonExpired}
			return Settlement{}, nil
		}
		keepUser, linked, lerr := s.store.LinkedUser(ctx, g.Org, workspace, by)
		if lerr != nil {
			return Settlement{}, ErrUnavailable
		}
		if !linked {
			out = Outcome{Kind: Refused, Reason: ReasonUnlinkedUser}
			return Settlement{}, nil
		}
		// The link only says who answered; whether they may decide is their
		// role in the secret's scope.
		if s.approvers == nil {
			return Settlement{}, ErrUnavailable
		}
		a, gerr := s.approvals.Get(ctx, g.Org, g.Approval)
		if gerr != nil {
			return Settlement{}, ErrUnavailable
		}
		may, perr := s.approvers.CanApprove(ctx, g.Org, keepUser, a.Scope)
		if perr != nil {
			return Settlement{}, ErrUnavailable
		}
		if !may {
			out = Outcome{Kind: Refused, Reason: ReasonNotApprover}
			return Settlement{}, nil
		}
		// A fixed text goes with the decision: the person's words never reach
		// the journal.
		aerr := s.approvals.Decide(ctx, g.Org, g.Approval, keepUser, approve, hex.EncodeToString(g.Hash[:]))
		switch {
		case aerr == nil:
		case errors.Is(aerr, ErrAlreadyDecided):
			// Decide committed in its own transaction: an earlier delivery may
			// have decided the approval and then failed to mark this gate. Bring
			// the gate in line with what the approval says, so the sweep never
			// cancels a card of a request that was decided.
			out = Outcome{Kind: Duplicate}
			cur, gerr := s.approvals.Get(ctx, g.Org, g.Approval)
			if gerr == nil && (cur.Status == "approved" || cur.Status == "rejected") {
				return Settlement{Status: cur.Status, MeshUser: by, EventID: eventID, DecidedAt: s.now()}, nil
			}
			return Settlement{}, nil
		case errors.Is(aerr, ErrBinding):
			out = Outcome{Kind: Refused, Reason: ReasonHashMismatch}
			return Settlement{}, nil
		case errors.Is(aerr, ErrSelf):
			out = Outcome{Kind: Refused, Reason: ReasonInitiator}
			return Settlement{}, nil
		case errors.Is(aerr, ErrNotHuman):
			out = Outcome{Kind: Refused, Reason: ReasonNotUser}
			return Settlement{}, nil
		case errors.Is(aerr, ErrExpired):
			out = Outcome{Kind: Refused, Reason: ReasonExpired}
			return Settlement{}, nil
		case errors.Is(aerr, ErrNotExecutable):
			out = Outcome{Kind: Refused, Reason: ReasonNotExecutable}
			return Settlement{}, nil
		default:
			return Settlement{}, ErrUnavailable
		}
		st := "rejected"
		out = Outcome{Kind: Rejected}
		if approve {
			st, out = "approved", Outcome{Kind: Approved}
		}
		return Settlement{Status: st, MeshUser: by, EventID: eventID, DecidedAt: s.now()}, nil
	})
	if errors.Is(err, ErrUnknownGate) {
		return refuse(ReasonUnknownGate)
	}
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	if out.Kind == Refused {
		return refuse(out.Reason)
	}
	return out, nil
}

// ErrUnknownGate is returned by Store.Settle for a gate that does not exist.
var ErrUnknownGate = errors.New("meshgate: no such gate")

// parseDecision reads the first word of the answer. Anything else is no
// decision: a card is never approved by an unclear reply.
func parseDecision(text string) (approve, ok bool) {
	f := strings.Fields(text)
	if len(f) == 0 {
		return false, false
	}
	switch strings.ToLower(strings.Trim(f[0], ".,:;!")) {
	case "approve", "approved":
		return true, true
	case "reject", "rejected":
		return false, true
	}
	return false, false
}

// WithClock replaces the time source, for tests.
func (s *Service) WithClock(now func() time.Time) *Service {
	s.now = now
	return s
}

// Sweep ends the requests whose deadline passed: the gate is marked expired
// (the approval itself lapses by its own TTL and can no longer be approved)
// and the card is cancelled. A card Mesh will not close stays marked for the
// next sweep. It returns how many cards were cancelled.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	if s.cards == nil {
		return 0, ErrUnavailable
	}
	gs, err := s.store.Lapsed(ctx, s.now())
	if err != nil {
		return 0, ErrUnavailable
	}
	n := 0
	for _, g := range gs {
		if err := s.cards.Cancel(ctx, g.TaskID.String(), "request expired"); err != nil {
			s.log.LogAttrs(ctx, slog.LevelWarn, "mesh gate card not cancelled", slog.String("workspace_id", g.Workspace.String()), slog.String("task_id", g.TaskID.String()))
			continue
		}
		if s.store.CardCancelled(ctx, g.Workspace, g.TaskID) != nil {
			continue
		}
		n++
	}
	return n, nil
}
