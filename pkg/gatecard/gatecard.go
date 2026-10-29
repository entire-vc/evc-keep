// Package gatecard is the contract between Keep's confirmation logic and a
// task tracker that shows a request as a card a person decides. Keep's core
// holds the invariants and talks to a tracker only through Cards; the Mesh
// plugin implements it, and no tracker is a dependency of the core.
//
// A card is a pointer to a request, never a copy of what it protects: Spec
// has no field that can carry a secret value, and its text is built from
// names, classes, ids and the request hash only.
package gatecard

import (
	"context"
	"errors"
	"time"
)

// ErrRefused: the tracker answered but would not do it (rights, a frozen
// card, an unknown id). Its text is not forwarded.
var ErrRefused = errors.New("gatecard: tracker refused")

// ErrUnavailable: the tracker could not be reached or answered something
// unusable. The call may be retried.
var ErrUnavailable = errors.New("gatecard: tracker unavailable")

// Spec is the card to create.
type Spec struct {
	// Title and Body say what is asked: secret name, class, target kind,
	// request id. No value, no provider text.
	Title string
	Body  string
	// ExternalRef names the Keep request ("keep:approval/<id>").
	ExternalRef string
	// RequestHash is the hex binding hash of the request. The tracker keeps it
	// write-once with the card and echoes it in the decision event, so a
	// decision applies only to the request that was shown.
	RequestHash string
	// Deadline is when the ask lapses; the card is cancelled after it.
	Deadline time.Time
}

// Cards creates and cancels the cards of confirmation requests.
type Cards interface {
	// Create makes the card, binds ExternalRef/RequestHash to it, arms the
	// human gate and returns the card id.
	Create(ctx context.Context, s Spec) (cardID string, err error)
	// Cancel closes a card whose request lapsed. A card the tracker will not
	// close is ErrRefused.
	Cancel(ctx context.Context, cardID, reason string) error
}
