package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	intakeweb "github.com/entire-vc/evc-keep/web/intake"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InputService takes only ciphertext and authenticated metadata.
type InputService interface {
	Issue(context.Context, tenancy.SecretRef, catalog.Store, audit.Actor, time.Duration) (intake.Issued, error)
	IssueRotation(context.Context, tenancy.SecretRef, catalog.Store, audit.Actor, time.Duration) (intake.Issued, error)
	Read(context.Context, string) (intake.View, error)
	Complete(context.Context, string, intake.Envelope) (intake.Result, error)
	Status(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (intake.Result, error)
}

type inputRoutes struct {
	sec  *secretRoutes
	svc  InputService
	pool *pgxpool.Pool
}

func inputHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", intakeweb.CSP())
}

func decodeInput(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return intake.ErrInvalid
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return intake.ErrInvalid
	}
	return nil
}

func inputError(w http.ResponseWriter, r *http.Request, err error) {
	status, class, message := http.StatusServiceUnavailable, apperr.ClassNotReady, "input service unavailable"
	switch {
	case errors.Is(err, intake.ErrGone):
		status, class, message = http.StatusGone, apperr.ClassNotFound, "input link is unavailable"
	case errors.Is(err, intake.ErrRejected), errors.Is(err, intake.ErrInvalid):
		status, class, message = http.StatusBadRequest, apperr.ClassInvalidArgument, "input request rejected"
	case errors.Is(err, intake.ErrPending):
		status, class, message = http.StatusAccepted, apperr.ClassNotReady, "input is pending"
	}
	writeError(w, status, class, message, reqid.FromContext(r.Context()))
}

func (s *inputRoutes) issue(w http.ResponseWriter, r *http.Request) {
	inputHeaders(w)
	var body struct {
		Secret    string `json:"secret"`
		TTL       string `json:"ttl"`
		Workspace string `json:"workspace_id"`
		Project   string `json:"project_id"`
	}
	if decodeInput(w, r, 8192, &body) != nil || body.Secret == "" {
		inputError(w, r, intake.ErrInvalid)
		return
	}
	var ttl time.Duration
	var err error
	if body.TTL != "" {
		ttl, err = time.ParseDuration(body.TTL)
		if err != nil || ttl <= 0 || ttl > 24*time.Hour {
			inputError(w, r, intake.ErrInvalid)
			return
		}
	}
	p, _ := identity.FromContext(r.Context())
	tc := contextFromRequest(r, p)
	for _, item := range []struct {
		raw string
		dst *uuid.UUID
	}{{body.Workspace, &tc.Workspace}, {body.Project, &tc.Project}} {
		if item.raw != "" {
			*item.dst, err = uuid.Parse(item.raw)
			if err != nil {
				inputError(w, r, intake.ErrInvalid)
				return
			}
		}
	}
	ref, err := catalog.ResolveAuthorized(r.Context(), s.sec.tr, s.sec.ir, tc, body.Secret)
	if err != nil {
		writeAppError(w, err, reqid.FromContext(r.Context()))
		return
	}
	perms, err := catalog.PermissionsAt(r.Context(), s.sec.ir, tc, ref.Scope)
	if err != nil {
		writeAppError(w, err, reqid.FromContext(r.Context()))
		return
	}
	if !perms[identity.PermRotate] || (p.Scope != "" && p.Scope != ref.Scope.String()) {
		writeAppError(w, catalog.NotFoundByID(ref.ID), reqid.FromContext(r.Context()))
		return
	}
	st, err := s.sec.cat.GetStore(r.Context(), p.OrgID, ref.StoreID)
	if err != nil {
		writeAppError(w, err, reqid.FromContext(r.Context()))
		return
	}
	if s.svc == nil {
		inputError(w, r, intake.ErrUnavailable)
		return
	}
	actor := audit.Actor{Type: actorType(p.Kind), ID: p.ID.String(), Via: audit.ViaAPI}
	if p.SponsorUserID != nil {
		actor.SponsorID = p.SponsorUserID.String()
	}
	link, err := s.svc.Issue(r.Context(), ref, st, actor, ttl)
	if err != nil {
		inputError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, link)
}

func (s *inputRoutes) complete(w http.ResponseWriter, r *http.Request) {
	inputHeaders(w)
	var env intake.Envelope
	if decodeInput(w, r, 1500000, &env) != nil {
		inputError(w, r, intake.ErrInvalid)
		return
	}
	if s.svc == nil {
		inputError(w, r, intake.ErrUnavailable)
		return
	}
	result, err := s.svc.Complete(r.Context(), r.PathValue("token"), env)
	if err != nil {
		inputError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *inputRoutes) status(w http.ResponseWriter, r *http.Request) {
	inputHeaders(w)
	id, err := uuid.Parse(r.PathValue("request_id"))
	if err != nil {
		inputError(w, r, intake.ErrGone)
		return
	}
	if s.svc == nil {
		inputError(w, r, intake.ErrUnavailable)
		return
	}
	p, _ := identity.FromContext(r.Context())
	var scope tenancy.Scope
	var kind string
	err = s.pool.QueryRow(r.Context(), `SELECT s.scope_level,s.scope_id,l.actor_type FROM intake_links l JOIN secrets s ON s.org_id=l.org_id AND s.id=l.secret_id WHERE l.org_id=$1 AND l.actor_id=$2 AND l.request_id=$3`, p.OrgID, p.ID.String(), id).Scan(&scope.Level, &scope.ID, &kind)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		inputError(w, r, intake.ErrUnavailable)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) || kind != string(actorType(p.Kind)) || (p.Scope != "" && p.Scope != scope.String()) {
		inputError(w, r, intake.ErrGone)
		return
	}
	perms, err := catalog.PermissionsAt(r.Context(), s.sec.ir, contextFromRequest(r, p), scope)
	if err != nil {
		inputError(w, r, intake.ErrUnavailable)
		return
	}
	if !perms[identity.PermReadMetadata] {
		inputError(w, r, intake.ErrGone)
		return
	}
	result, err := s.svc.Status(r.Context(), p.OrgID, p.ID, id)
	if err != nil {
		inputError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *inputRoutes) page(w http.ResponseWriter, r *http.Request) {
	inputHeaders(w)
	if s.svc == nil {
		inputError(w, r, intake.ErrUnavailable)
		return
	}
	v, err := s.svc.Read(r.Context(), r.PathValue("token"))
	if err != nil {
		inputError(w, r, err)
		return
	}
	// Render before writing: a template error must not send a partial page.
	var page strings.Builder
	err = intakeweb.Render(&page, intakeweb.Page{RequestID: v.RequestID, SecretName: v.SecretName, Scope: v.Scope, StoreName: v.StoreName, Class: v.Class, RequestedBy: v.RequestedBy, Sponsor: v.Sponsor, PublicKey: base64.StdEncoding.EncodeToString(v.PublicKey), SigningKey: base64.StdEncoding.EncodeToString(v.SigningKey), Signature: base64.StdEncoding.EncodeToString(v.Signature)})
	if err != nil {
		inputError(w, r, intake.ErrUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, page.String())
}

func inputScript(w http.ResponseWriter, _ *http.Request) {
	inputHeaders(w)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = io.WriteString(w, intakeweb.Script())
}
