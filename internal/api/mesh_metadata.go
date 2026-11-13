package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/google/uuid"
)

// MeshMetadataReader is the zone's narrow reader behind the metadata probe:
// the version and the length of the newest active version of a ref in the
// workspace's own namespace, read without opening it. The concrete type is
// the same MeshVault; it is a separate interface so that a vault without it
// answers the probe with "metadata unavailable" instead of a fallback.
type MeshMetadataReader interface {
	MetadataSecret(ctx context.Context, org, workspace, ref string) (MeshSecretMeta, error)
}

const (
	meshMetadataBodyLimit = 4096
	// A bounded budget of its own per workspace: 60 a minute, a burst of 10.
	meshMetadataPerMinute = 60
	meshMetadataBurst     = 10

	msgMetadataInvalid     = "invalid metadata request"
	msgMetadataUnavailable = "metadata unavailable"
	msgMetadataLimited     = "request rate limited"
	msgMetadataTooLarge    = "metadata request too large"
)

// metadataRoutes is the Mesh routes plus the probe's own budget. The budget
// lives here, not in meshRoutes, so the probe adds nothing to that struct.
type metadataRoutes struct {
	*meshRoutes
	limit *limiter
}

var metadataActorMsgs = actorMsgs{db: msgMetadataUnavailable, journal: msgMetadataUnavailable, limited: msgMetadataLimited}

// meshMetadataAnswer is the whole of the probe's success body: a closed
// struct, so nothing else can reach the wire.
type meshMetadataAnswer struct {
	Version   string `json:"version"`
	Length    int    `json:"length"`
	RequestID string `json:"request_id"`
}

// handleMetadataSecret serves GET /orgs/{org_id}/mesh/secrets/{ref}/metadata.
// The signature is the authentication (the same one as PUT and resolve, over
// the method and the path, so it serves no other route); the answer is the
// version and the length of the stored secret, never a value. Every verified
// call is journaled and answered only once its record is written; a journal
// or a nonce store that fails gives 503 and no metadata.
func (m *metadataRoutes) handleMetadataSecret(w http.ResponseWriter, r *http.Request) {
	requestID := reqid.FromContext(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, apperr.ClassInvalidArgument, msgMetadataInvalid, requestID)
		return
	}
	reader, ok := m.deps.Vault.(MeshMetadataReader)
	if !ok || m.aud == nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, msgMetadataUnavailable, requestID)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, meshMetadataBodyLimit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, apperr.ClassPayloadTooLarge, msgMetadataTooLarge, requestID)
			return
		}
		writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, msgMetadataInvalid, requestID)
		return
	}
	ws, org, ok := m.secretActorMsgs(w, r, requestID, audit.ActionMeshSecretMetadata, body, metadataActorMsgs)
	if !ok {
		return
	}
	if allowed, wait := m.limit.take(bucketKey{org: org, id: ws}); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		m.metadataRefuse(w, r, org, ws, http.StatusTooManyRequests, apperr.ClassRateLimited, msgMetadataLimited, audit.ErrClassPolicyDenied)
		return
	}
	// The body was part of the signature; the probe takes none, no query, and
	// no way to send a body of unknown length.
	ref := r.PathValue("ref")
	if len(body) != 0 || r.URL.RawQuery != "" || r.ContentLength > 0 || len(r.TransferEncoding) != 0 || !meshRefValid(ref) {
		m.metadataRefuse(w, r, org, ws, http.StatusBadRequest, apperr.ClassInvalidArgument, msgMetadataInvalid, audit.ErrClassInvalidArgument)
		return
	}
	meta, err := reader.MetadataSecret(r.Context(), org.String(), ws.String(), ref)
	switch {
	case errors.Is(err, ErrMeshSecretNotFound):
		m.metadataRefuse(w, r, org, ws, http.StatusNotFound, apperr.ClassNotFound, "not found", audit.ErrClassNotFound)
		return
	case errors.Is(err, ErrMeshSecretInvalid):
		m.metadataRefuse(w, r, org, ws, http.StatusBadRequest, apperr.ClassInvalidArgument, msgMetadataInvalid, audit.ErrClassInvalidArgument)
		return
	case err != nil:
		m.metadataRefuse(w, r, org, ws, http.StatusServiceUnavailable, apperr.ClassNotReady, msgMetadataUnavailable, audit.ErrClassInternal)
		return
	}
	meta.Fingerprint = ""
	if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretMetadata, ref, meta, audit.StatusOK, audit.ErrClassNone); err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, msgMetadataUnavailable, requestID)
		return
	}
	out, err := json.Marshal(meshMetadataAnswer{Version: meta.Version, Length: meta.Length, RequestID: requestID})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, msgMetadataUnavailable, requestID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// metadataRefuse journals a refusal after authentication, nameless, and
// answers it only once the record is written: a call the journal does not
// hold gets a 503.
func (m *metadataRoutes) metadataRefuse(w http.ResponseWriter, r *http.Request, org, ws uuid.UUID, status int, class apperr.Class, msg string, ec audit.ErrorClass) {
	requestID := reqid.FromContext(r.Context())
	if err := m.auditSecret(r, org, ws, audit.ActionMeshSecretMetadata, "", MeshSecretMeta{}, audit.StatusFailed, ec); err != nil {
		w.Header().Del("Retry-After")
		writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, msgMetadataUnavailable, requestID)
		return
	}
	writeError(w, status, class, msg, requestID)
}
