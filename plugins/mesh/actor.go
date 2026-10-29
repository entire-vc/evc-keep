package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

// ErrSameActor refuses a start whose self-rotation account is the actor whose
// token the gate holds. Two owners of one actor's token kill each other's
// copy: a rotate-token of the gate ends the sealed service token, and a
// self-rotation ends the gate's. It names neither the actor nor the token.
var ErrSameActor = errors.New("self-rotation account is the gate's actor")

// ActorCheck configures CheckSelfRotateActor.
type ActorCheck struct {
	BaseURL string
	// AccountID is the self-rotation account (KEEP_MESH_SELF_ROTATE_ACCOUNT_ID).
	AccountID string
	// Gate returns the gate's actor token; required.
	Gate TokenSource
	HTTP *http.Client
	Log  *slog.Logger
}

// CheckSelfRotateActor asks Mesh whose token the gate holds (GET /ext/me) and
// refuses with ErrSameActor when it is the self-rotation account. An answer it
// cannot get or read does not fail the start, since the gate then answers 503
// anyway: it is logged by class and nil is returned. A configuration the check
// cannot run with is ErrConfig. Nothing of the token or the answer is logged.
func CheckSelfRotateActor(ctx context.Context, c ActorCheck) error {
	account, err := uuid.Parse(c.AccountID)
	if err != nil || c.Gate == nil {
		return ErrConfig
	}
	x, err := NewExtSelf(ExtConfig{BaseURL: c.BaseURL, AccountID: c.AccountID, TokenSource: c.Gate, HTTP: c.HTTP, Log: c.Log})
	if err != nil {
		return ErrConfig
	}
	gate, err := x.actorID(ctx)
	if err != nil {
		x.log.Warn("mesh self-rotation actor check skipped", "error_class", class(err))
		return nil
	}
	if gate == account {
		x.log.Error("mesh self-rotation refused", "error_class", "same_actor")
		return ErrSameActor
	}
	x.log.Info("mesh self-rotation actor check passed")
	return nil
}

// actorID is the actor_id of the token the source holds. A missing or
// malformed id is ErrBadAnswer; the body is cleared and never forwarded.
func (e *ExtSelf) actorID(ctx context.Context) (uuid.UUID, error) {
	raw, err := e.do(ctx, http.MethodGet, "/me", "", nil, http.StatusOK)
	if err != nil {
		return uuid.Nil, err
	}
	var a struct {
		ActorID string `json:"actor_id"`
	}
	derr := json.NewDecoder(bytes.NewReader(raw)).Decode(&a)
	clear(raw)
	id, perr := uuid.Parse(a.ActorID)
	if derr != nil || perr != nil {
		return uuid.Nil, ErrBadAnswer
	}
	return id, nil
}
