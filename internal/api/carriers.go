package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/carriers"
	"github.com/entire-vc/evc-keep/internal/catalog"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// CarrierService registers and lists the destinations a secret is laid into.
// Both calls take the organization from the authenticated principal.
type CarrierService interface {
	Register(ctx context.Context, org, secret uuid.UUID, version string, md carriers.Metadata) (carriers.Carrier, error)
	List(ctx context.Context, org, secret uuid.UUID) ([]carriers.Carrier, error)
}

// Carrier is the §4.3 Carrier row. It carries no fingerprint text and no
// version: fingerprint_match only says whether the destination still holds
// the secret's current version.
type Carrier struct {
	ID               string        `json:"id"`
	SecretID         string        `json:"secret_id"`
	Host             string        `json:"host"`
	RunnerID         string        `json:"runner_id,omitempty"`
	Target           CarrierTarget `json:"target"`
	Consumer         string        `json:"consumer,omitempty"`
	Healthcheck      string        `json:"healthcheck,omitempty"`
	Status           string        `json:"status"`
	LastVerifiedAt   *time.Time    `json:"last_verified_at,omitempty"`
	FingerprintMatch bool          `json:"fingerprint_match"`
}

type carrierRoutes struct {
	sec *secretRoutes
	svc CarrierService
}

// registerBody is the whole request: the destination and the version it was
// deployed at. A fingerprint, a value or any other field is refused by the
// strict decoder, and the fingerprint is taken from the deployment record.
type registerBody struct {
	Version     string `json:"version"`
	Host        string `json:"host"`
	TargetKind  string `json:"target_kind"`
	TargetPath  string `json:"target_path"`
	TargetField string `json:"target_field"`
	Consumer    string `json:"consumer"`
}

// cleanText reports whether s is text of at most max runes with no control
// characters; an empty s is allowed only when optional.
func cleanText(s string, max int, optional bool) bool {
	if s == "" {
		return optional
	}
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= max && !strings.ContainsFunc(s, unicode.IsControl)
}

func (b registerBody) metadata() (carriers.Metadata, bool) {
	known := false
	for _, k := range runnerproto.TargetKinds {
		known = known || string(k) == b.TargetKind
	}
	if !known || !cleanText(b.Version, 128, false) || !cleanText(b.Host, 253, false) || !cleanText(b.TargetPath, 4096, false) ||
		!cleanText(b.TargetField, 256, true) || !cleanText(b.Consumer, 256, true) {
		return carriers.Metadata{}, false
	}
	return carriers.Metadata{Host: b.Host, TargetKind: runnerproto.TargetKind(b.TargetKind), TargetPath: b.TargetPath,
		TargetField: b.TargetField, Consumer: b.Consumer}, true
}

// secretByID resolves {secret_id} for a caller holding perm at its scope. A
// secret that is missing, foreign, or whose right the caller lacks is the
// same 404; ok is false once the answer has been written.
func secretByID(w http.ResponseWriter, r *http.Request, sec *secretRoutes, perm identity.Permission) (id uuid.UUID, scope tenancy.Scope, p identity.Principal, ok bool) {
	rid := reqid.FromContext(r.Context())
	p, _ = identity.FromContext(r.Context())
	id, err := uuid.Parse(r.PathValue("secret_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "secret_id is not a valid id", rid)
		return uuid.Nil, tenancy.Scope{}, p, false
	}
	tc := contextFromRequest(r, p)
	found, err := sec.cat.Meta(r.Context(), p.OrgID, id, reachableScopes(tc))
	if err != nil {
		writeAppError(w, err, rid)
		return uuid.Nil, tenancy.Scope{}, p, false
	}
	perms, err := catalog.PermissionsAt(r.Context(), sec.ir, tc, found.Scope)
	if err != nil {
		writeAppError(w, err, rid)
		return uuid.Nil, tenancy.Scope{}, p, false
	}
	if !perms[perm] || (p.Scope != "" && p.Scope != found.Scope.String()) {
		writeAppError(w, catalog.NotFoundByID(id), rid)
		return uuid.Nil, tenancy.Scope{}, p, false
	}
	return id, found.Scope, p, true
}

func (c *carrierRoutes) secretFor(w http.ResponseWriter, r *http.Request, perm identity.Permission) (id uuid.UUID, p identity.Principal, ok bool) {
	id, _, p, ok = secretByID(w, r, c.sec, perm)
	if ok && c.svc == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "carrier service unavailable", reqid.FromContext(r.Context()))
		return uuid.Nil, p, false
	}
	return id, p, ok
}

// currentFingerprint is the fingerprint of the secret's newest enabled
// version, the one a carrier must hold to count as matching.
func (c *carrierRoutes) currentFingerprint(r *http.Request, org, id uuid.UUID) (string, error) {
	versions, err := c.sec.cat.ListVersions(r.Context(), org, id)
	if err != nil {
		return "", err
	}
	for _, v := range versions {
		if !v.Disabled {
			return v.Fingerprint, nil
		}
	}
	return "", nil
}

func newCarrier(c carriers.Carrier, current string) Carrier {
	runner := ""
	if c.RunnerID != uuid.Nil {
		runner = c.RunnerID.String()
	}
	return Carrier{ID: c.ID.String(), SecretID: c.SecretID.String(), Host: c.Host, RunnerID: runner,
		Target: CarrierTarget{Kind: string(c.TargetKind), Path: c.TargetPath}, Consumer: c.Consumer, Healthcheck: c.HealthcheckRef,
		Status: string(c.State), LastVerifiedAt: c.LastVerifiedAt, FingerprintMatch: current != "" && c.LastFP == current}
}

// carrierError answers a service failure with a closed class and a template
// that names neither the host nor the path.
func carrierError(w http.ResponseWriter, id uuid.UUID, err error, rid string) {
	switch {
	case errors.Is(err, carriers.ErrNotFound):
		writeAppError(w, catalog.NotFoundByID(id), rid)
	case errors.Is(err, carriers.ErrMetadata):
		writeError(w, http.StatusForbidden, apperr.ClassMetadataNotApproved, "carrier destination is not approved for this secret", rid)
	case errors.Is(err, carriers.ErrDeployment), errors.Is(err, carriers.ErrFingerprint):
		writeError(w, http.StatusConflict, apperr.ClassDeploymentNotConfirmed, "no confirmed deployment of this version to this destination", rid)
	default:
		writeError(w, http.StatusInternalServerError, apperr.ClassInternal, "internal error", rid)
	}
}

func (c *carrierRoutes) register(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	id, p, ok := c.secretFor(w, r, identity.PermDeploy)
	if !ok {
		return
	}
	var body registerBody
	if decodeInput(w, r, 8192, &body) != nil {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid carrier request", rid)
		return
	}
	md, valid := body.metadata()
	if !valid {
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid carrier request", rid)
		return
	}
	got, err := c.svc.Register(r.Context(), p.OrgID, id, body.Version, md)
	if err != nil {
		carrierError(w, id, err, rid)
		return
	}
	current, err := c.currentFingerprint(r, p.OrgID, id)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	writeJSON(w, http.StatusCreated, newCarrier(got, current))
}

func (c *carrierRoutes) list(w http.ResponseWriter, r *http.Request) {
	deployHeaders(w)
	rid := reqid.FromContext(r.Context())
	id, p, ok := c.secretFor(w, r, identity.PermReadMetadata)
	if !ok {
		return
	}
	rows, err := c.svc.List(r.Context(), p.OrgID, id)
	if err != nil {
		carrierError(w, id, err, rid)
		return
	}
	current, err := c.currentFingerprint(r, p.OrgID, id)
	if err != nil {
		writeAppError(w, err, rid)
		return
	}
	out := make([]Carrier, 0, len(rows))
	for _, row := range rows {
		out = append(out, newCarrier(row, current))
	}
	writeJSON(w, http.StatusOK, out)
}
