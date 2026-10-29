package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/pkg/gatecard"
	"github.com/google/uuid"
)

// gatePredicate is the answer to the gate checklist: the decision belongs to a
// linked person, nothing blocks them from deciding, and a rejected request can
// be asked again. Answering that the asker holds the credential would tell
// Mesh nobody needs to be asked, and it refuses the gate.
const gatePredicate = `{"credential_exists":false,"credential_reason":"only a linked person may decide; Keep refuses an answer from an agent",` +
	`"reversible":true,"reversible_reason":"a rejected request can be asked again",` +
	`"blocked_by_other_task":false,"blocked_reason":"not waiting for another task",` +
	`"customer_visible_now":false,"customer_reason":"no customer sees this task"}`

// This file is the Mesh side of confirmations: a request waiting for a person
// becomes a card with a human gate. Calls, all authenticated as the extension
// actor of the workspace:
//
//	POST   /api/v1/projects/{project}/tasks     create the card
//	PUT    /api/v1/tasks/{id}/external-ref      bind the request ref and its hash (write-once)
//	POST   /api/v1/tasks/{id}/human-gate        arm the gate, with the deadline
//	POST   /api/v1/tasks/{id}/move              cancel a lapsed card
//
// The card carries names, ids and the request hash, never a value; a response
// body is never logged and never forwarded in an error.

// GateConfig configures Gates.
type GateConfig struct {
	BaseURL string
	// ProjectID is the Mesh project the cards are created in.
	ProjectID string
	// CancelStatusID is the project's cancelled status, used by Cancel.
	CancelStatusID string
	TokenSource    TokenSource
	HTTP           *http.Client
	Log            *slog.Logger
}

// Gates implements gatecard.Cards over the Mesh API.
type Gates struct {
	base      *url.URL
	project   string
	cancelled string
	src       TokenSource
	hc        *http.Client
	log       *slog.Logger
}

var _ gatecard.Cards = (*Gates)(nil)

// NewGates validates cfg: https (or loopback http), UUID ids, a token source.
func NewGates(cfg GateConfig) (*Gates, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || cfg.TokenSource == nil || !validUUID(cfg.ProjectID) ||
		(cfg.CancelStatusID != "" && !validUUID(cfg.CancelStatusID)) ||
		(u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname()))) {
		return nil, ErrConfig
	}
	hc := &http.Client{Timeout: defaultTimeout}
	if cfg.HTTP != nil {
		c := *cfg.HTTP
		hc = &c
	}
	// A redirect would carry the bearer token elsewhere: refuse it.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Gates{base: u, project: cfg.ProjectID, cancelled: cfg.CancelStatusID, src: cfg.TokenSource, hc: hc, log: log}, nil
}

func validUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

// String and GoString keep the client from printing its fields.
func (*Gates) String() string   { return "mesh.Gates" }
func (*Gates) GoString() string { return "mesh.Gates" }

// Create implements gatecard.Cards. A card that was created but could not be
// bound or armed is cancelled: Keep would not recognise an answer to it.
func (g *Gates) Create(ctx context.Context, s gatecard.Spec) (string, error) {
	body, err := g.do(ctx, http.MethodPost, "/projects/"+g.project+"/tasks", map[string]any{
		"title": s.Title, "description": s.Body, "priority": "high", "labels": []string{"keep", "confirmation"},
	}, http.StatusOK, http.StatusCreated)
	if err != nil {
		g.journal("create", "", err)
		return "", err
	}
	var a struct {
		ID   string `json:"id"`
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	if json.Unmarshal(body, &a) != nil {
		g.journal("create", "", ErrBadAnswer)
		return "", gatecard.ErrUnavailable
	}
	id := a.ID
	if id == "" {
		id = a.Task.ID
	}
	if !validUUID(id) {
		g.journal("create", "", ErrBadAnswer)
		return "", gatecard.ErrUnavailable
	}
	if _, err = g.do(ctx, http.MethodPut, "/tasks/"+id+"/external-ref",
		map[string]string{"external_ref": s.ExternalRef, "external_hash": s.RequestHash}, http.StatusOK); err == nil {
		_, err = g.do(ctx, http.MethodPost, "/tasks/"+id+"/human-gate", map[string]any{
			"reason": "Keep asks a person to approve or reject this request. Answer with the word approve or reject.",
			"class":  "hard", "deadline": s.Deadline.UTC().Format(time.RFC3339),
			// Mesh requires a default for a gate nobody answers. Reject: applied at
			// the deadline it is not a person's decision, so Keep refuses it too.
			"recommended_default": "reject",
			"predicate":           json.RawMessage(gatePredicate),
		}, http.StatusOK, http.StatusCreated)
	}
	if err != nil {
		_ = g.Cancel(context.WithoutCancel(ctx), id, "request not bound")
		g.journal("create", id, err)
		return "", err
	}
	g.journal("create", id, nil)
	return id, nil
}

// Cancel implements gatecard.Cards. Mesh keeps a card with a human gate from
// being closed by anyone but a person; that refusal is ErrRefused, and the
// caller keeps the card marked for another try.
func (g *Gates) Cancel(ctx context.Context, cardID, reason string) error {
	if !validUUID(cardID) || g.cancelled == "" {
		return gatecard.ErrRefused
	}
	_, err := g.do(ctx, http.MethodPost, "/tasks/"+cardID+"/move", map[string]string{"status_id": g.cancelled, "reason": reason}, http.StatusOK)
	g.journal("cancel", cardID, err)
	return err
}

func (g *Gates) do(ctx context.Context, method, path string, payload any, ok ...int) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, gatecard.ErrUnavailable
	}
	u := *g.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1" + path
	r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, gatecard.ErrUnavailable
	}
	tok, terr := g.src(ctx)
	if terr != nil || tok == "" {
		// The source's error text is not forwarded.
		return nil, gatecard.ErrUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+string(tok))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	resp, err := g.hc.Do(r)
	if err != nil {
		// A transport error text may carry the URL; it is not forwarded.
		return nil, gatecard.ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	for _, c := range ok {
		if resp.StatusCode == c {
			if rerr != nil {
				return nil, gatecard.ErrUnavailable
			}
			return body, nil
		}
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusBadRequest:
		return nil, gatecard.ErrRefused
	}
	return nil, gatecard.ErrUnavailable
}

func (g *Gates) journal(op, card string, err error) {
	attrs := []slog.Attr{slog.String("kind", op)}
	if card != "" {
		attrs = append(attrs, slog.String("task_id", card))
	}
	if err != nil {
		attrs = append(attrs, slog.String("status", "failed"))
		g.log.LogAttrs(context.Background(), slog.LevelWarn, "mesh gate "+op, attrs...)
		return
	}
	attrs = append(attrs, slog.String("status", "ok"))
	g.log.LogAttrs(context.Background(), slog.LevelInfo, "mesh gate "+op, attrs...)
}
