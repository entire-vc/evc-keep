package meshext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Entity states. Nothing in this file deletes a row: an entity that Mesh no
// longer reports is marked orphaned, so the secrets and the access that hang
// off it survive a missed or mistaken event (tenancy model section 2).
const (
	StatusActive   = "active"
	StatusRemoved  = "removed"
	StatusRevoked  = "revoked"
	StatusOrphaned = "orphaned"
)

// GateDecided is the type of a confirmation card answer.
const GateDecided = "task.gate.decided"

// EventData is the optional body of a hierarchy event. Every field is
// optional on the wire: an event that does not carry what it needs to be
// applied still counts, and makes the next reconciliation fetch a full
// snapshot instead of trusting its cursor.
type EventData struct {
	UserID        *uuid.UUID `json:"user_id"`
	Role          string     `json:"role"`
	ProjectID     *uuid.UUID `json:"project_id"`
	Slug          string     `json:"slug"`
	Name          string     `json:"name"`
	IsArchived    *bool      `json:"is_archived"`
	AgentID       *uuid.UUID `json:"agent_id"`
	KeyID         string     `json:"key_id"`
	Label         string     `json:"label"`
	SponsorUserID *uuid.UUID `json:"sponsor_user_id"`
}

// Event is one accepted, signed Mesh event. At is when the fact happened in
// Mesh (the event's occurred_at, else the moment Keep received it); a row only
// moves forward in At, which makes reordered deliveries harmless.
type Event struct {
	ID   string
	Type string
	At   time.Time
	Data *EventData
	// The payload of task.gate.decided (a confirmation card answer). The
	// decision is free text a person wrote: it is read for its first word and
	// never logged or stored.
	TaskID        string
	Decision      string
	DecidedBy     string
	DecidedByType string
	ExternalHash  string
	// Timed is true when the sender stated when the change happened. Only a
	// stated time can order an event against others; Keep's receipt time
	// cannot, because a delayed old event would look newer than a later one.
	Timed bool
}

type wireEvent struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	WorkspaceID string     `json:"workspace_id"`
	OccurredAt  *time.Time `json:"occurred_at"`
	Data        *EventData `json:"data"`

	TaskID        string `json:"task_id"`
	Decision      string `json:"decision"`
	DecidedBy     string `json:"decided_by"`
	DecidedByType string `json:"decided_by_type"`
	ExternalHash  string `json:"external_hash"`
}

// ErrBadEvent marks an event that is signed but malformed.
var ErrBadEvent = errors.New("meshext: invalid event")

// maxFuture bounds how far ahead of Keep's clock an event may claim to have
// happened, so a skewed or hostile timestamp cannot pin a row in the future
// and make every later change look stale.
const maxFuture = 5 * time.Minute

// ParseEvent decodes and validates an event body for workspace ws. now is
// Keep's clock. The signature covers the timestamp and the body, not the
// headers, so X-Mesh-Event (headerType) and X-Mesh-Delivery (headerDelivery)
// are untrusted input. A body that carries its own id and type (the envelope
// form) is fully signed and uses them. Mesh's flat form (workspace_id plus the
// fields of the change) has no id or type of its own (the body has no `type`):
//   - a body with the fields of a gate answer (task_id and decision) is a gate
//     answer whatever the header says, and its id is derived from the signed
//     body alone, so a header edit cannot replay an answer;
//   - otherwise X-Mesh-Event is only a label of a hierarchy change, which a flat
//     event never applies (an occurred_at in the body is ignored, so the event
//     is untimed and only makes the next reconciliation fetch a full
//     snapshot); the gate type there is refused, so a hierarchy body cannot be
//     relabelled into a gate no-op;
//   - the id of a flat hierarchy event is derived from the type, the delivery
//     id and the body. Mesh sends member.added and member.removed with the same
//     body, and re-signs every retry with a new timestamp, so the delivery id
//     is the only thing that is the same across retries of one send and
//     different between two sends. Whoever replays a signed request within the
//     timestamp window may mint a new id by editing the headers; the replay
//     only schedules a full fetch again. Without a delivery id the type still
//     separates added from removed; two sends of the same type and body
//     without a delivery id remain one event (the later one is dropped as a
//     repeat and only the next reconciliation picks it up).
//
// An unknown type, a workspace other than ws, a bad id or an out-of-shape field
// is ErrBadEvent.
func ParseEvent(body []byte, ws uuid.UUID, now time.Time, headerType, headerDelivery string) (Event, error) {
	var w wireEvent
	if err := json.Unmarshal(body, &w); err != nil {
		return Event{}, ErrBadEvent
	}
	if w.Type == "" { // Mesh's flat form: the body names neither type nor id
		if w.ID != "" {
			return Event{}, ErrBadEvent
		}
		h := sha256.New()
		switch {
		case w.TaskID != "" && w.Decision != "":
			w.Type = GateDecided
		case headerType != GateDecided:
			w.Type = headerType
			// The type is unsigned, so a stated time must not make the
			// event apply: a flat hierarchy event only schedules a fetch.
			w.OccurredAt = nil
			// Length-prefixed, so no split of the headers collides.
			for _, f := range []string{headerType, headerDelivery} {
				h.Write([]byte(strconv.Itoa(len(f)) + ":" + f))
			}
		}
		h.Write(body)
		w.ID = "flat:" + hex.EncodeToString(h.Sum(nil)[:20])
	}
	if w.Data == nil {
		var flat EventData
		if err := json.Unmarshal(body, &flat); err != nil {
			return Event{}, ErrBadEvent
		}
		w.Data = &flat
	}
	if w.WorkspaceID != ws.String() || !ValidEventID(w.ID) || !EventTypes[w.Type] {
		return Event{}, ErrBadEvent
	}
	at := now
	if w.OccurredAt != nil {
		at = *w.OccurredAt
		if at.After(now.Add(maxFuture)) {
			return Event{}, ErrBadEvent
		}
	}
	if d := w.Data; d != nil {
		if len(d.Role) > 64 || len(d.Slug) > 128 || len(d.Name) > 256 || len(d.Label) > 128 ||
			(d.KeyID != "" && !ValidEventID(d.KeyID)) ||
			!cleanText(d.Role, d.Slug, d.Name, d.Label) {
			return Event{}, ErrBadEvent
		}
	}
	return Event{ID: w.ID, Type: w.Type, At: at.UTC().Truncate(time.Microsecond), Data: w.Data, Timed: w.OccurredAt != nil,
		TaskID: w.TaskID, Decision: w.Decision, DecidedBy: w.DecidedBy, DecidedByType: w.DecidedByType, ExternalHash: w.ExternalHash}, nil
}

// cleanText reports whether every string is valid UTF-8 without a NUL byte,
// which PostgreSQL text cannot hold: one such value would make an event or a
// snapshot fail to store forever and freeze the mirror of the workspace.
func cleanText(ss ...string) bool {
	for _, s := range ss {
		if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
			return false
		}
	}
	return true
}

// Accept stores an event once and applies it, in one transaction: an event
// that was recorded is always applied, and a repeat of an event id has no
// effect. inserted is false for a repeat.
func (r *Repo) Accept(ctx context.Context, workspace uuid.UUID, ev Event) (inserted bool, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("meshext: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
INSERT INTO mesh_events (workspace_id, event_id, event_type) VALUES ($1, $2, $3)
ON CONFLICT (workspace_id, event_id) DO NOTHING`, workspace, ev.ID, ev.Type)
	if err != nil {
		return false, fmt.Errorf("meshext: record event: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	if err := applyEvent(ctx, tx, workspace, ev); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("meshext: commit event: %w", err)
	}
	return true, nil
}

// upsertProject merges one project fact. $7..$9 say which of slug, name and
// is_archived the fact states. Every field orders on its own clock, (stated
// at, value) with the larger winning, so the row is the same in whatever order
// partial facts arrive; status and orphaning follow the newest fact of any kind.
const upsertProject = `
INSERT INTO mesh_projects (workspace_id, project_id, slug, name, is_archived, slug_at, name_at, archived_at, status, state_at)
VALUES ($1, $2, CASE WHEN $7 THEN left($3,128) ELSE '' END, CASE WHEN $8 THEN left($4,256) ELSE '' END,
        CASE WHEN $9 THEN $5::boolean ELSE FALSE END,
        CASE WHEN $7 THEN $6::timestamptz ELSE 'epoch' END, CASE WHEN $8 THEN $6::timestamptz ELSE 'epoch' END,
        CASE WHEN $9 THEN $6::timestamptz ELSE 'epoch' END, 'active', $6)
ON CONFLICT (workspace_id, project_id) DO UPDATE SET
   slug = CASE WHEN $7 AND (mesh_projects.slug_at < $6 OR (mesh_projects.slug_at = $6 AND mesh_projects.slug < left($3,128)))
               THEN left($3,128) ELSE mesh_projects.slug END,
   slug_at = CASE WHEN $7 AND (mesh_projects.slug_at < $6 OR (mesh_projects.slug_at = $6 AND mesh_projects.slug < left($3,128)))
                  THEN $6::timestamptz ELSE mesh_projects.slug_at END,
   name = CASE WHEN $8 AND (mesh_projects.name_at < $6 OR (mesh_projects.name_at = $6 AND mesh_projects.name < left($4,256)))
               THEN left($4,256) ELSE mesh_projects.name END,
   name_at = CASE WHEN $8 AND (mesh_projects.name_at < $6 OR (mesh_projects.name_at = $6 AND mesh_projects.name < left($4,256)))
                  THEN $6::timestamptz ELSE mesh_projects.name_at END,
   is_archived = CASE WHEN $9 AND (mesh_projects.archived_at < $6 OR (mesh_projects.archived_at = $6 AND mesh_projects.is_archived < $5::boolean))
                      THEN $5::boolean ELSE mesh_projects.is_archived END,
   archived_at = CASE WHEN $9 AND (mesh_projects.archived_at < $6 OR (mesh_projects.archived_at = $6 AND mesh_projects.is_archived < $5::boolean))
                      THEN $6::timestamptz ELSE mesh_projects.archived_at END,
   status = CASE WHEN mesh_projects.state_at <= $6 THEN 'active' ELSE mesh_projects.status END,
   orphaned_at = CASE WHEN mesh_projects.state_at <= $6 THEN NULL ELSE mesh_projects.orphaned_at END,
   state_at = GREATEST(mesh_projects.state_at, $6), updated_at = now()`

// upsertMember merges one member fact. $6 says whether the fact states the
// role. The role orders on its own clock, so a later event that omits it cannot
// block an earlier one that carries it; status follows the newest fact of any kind.
const upsertMember = `
INSERT INTO mesh_members (workspace_id, user_id, role, role_at, status, state_at)
VALUES ($1, $2, CASE WHEN $6 THEN $3 ELSE 'member' END, CASE WHEN $6 THEN $5::timestamptz ELSE 'epoch' END, $4, $5)
ON CONFLICT (workspace_id, user_id) DO UPDATE SET
   role = CASE WHEN $6 AND (mesh_members.role_at < $5 OR (mesh_members.role_at = $5 AND mesh_members.role < $3))
               THEN $3 ELSE mesh_members.role END,
   role_at = CASE WHEN $6 AND (mesh_members.role_at < $5 OR (mesh_members.role_at = $5 AND mesh_members.role < $3))
                  THEN $5::timestamptz ELSE mesh_members.role_at END,
   status = CASE WHEN mesh_members.state_at < $5 OR (mesh_members.state_at = $5 AND mesh_members.status < $4)
                 THEN $4 ELSE mesh_members.status END,
   orphaned_at = CASE WHEN mesh_members.state_at < $5 OR (mesh_members.state_at = $5 AND mesh_members.status < $4)
                      THEN NULL ELSE mesh_members.orphaned_at END,
   state_at = GREATEST(mesh_members.state_at, $5), updated_at = now()`

// upsertAgent merges one agent fact. $6 and $7 say whether the fact states the
// slug and the sponsor (a snapshot states a missing sponsor as NULL; an event
// that omits it states nothing). Each orders on its own clock.
const upsertAgent = `
INSERT INTO mesh_agents (workspace_id, agent_id, slug, slug_at, sponsor_user_id, sponsor_at, status, state_at)
VALUES ($1, $2, CASE WHEN $6 THEN left($3,128) ELSE '' END, CASE WHEN $6 THEN $5::timestamptz ELSE 'epoch' END,
        CASE WHEN $7 THEN $4::uuid ELSE NULL END, CASE WHEN $7 THEN $5::timestamptz ELSE 'epoch' END, 'active', $5)
ON CONFLICT (workspace_id, agent_id) DO UPDATE SET
   slug = CASE WHEN $6 AND (mesh_agents.slug_at < $5 OR (mesh_agents.slug_at = $5 AND mesh_agents.slug < left($3,128)))
               THEN left($3,128) ELSE mesh_agents.slug END,
   slug_at = CASE WHEN $6 AND (mesh_agents.slug_at < $5 OR (mesh_agents.slug_at = $5 AND mesh_agents.slug < left($3,128)))
                  THEN $5::timestamptz ELSE mesh_agents.slug_at END,
   sponsor_user_id = CASE WHEN $7 AND (mesh_agents.sponsor_at < $5 OR (mesh_agents.sponsor_at = $5 AND
                              COALESCE(mesh_agents.sponsor_user_id::text, '') < COALESCE($4::text, '')))
                          THEN $4::uuid ELSE mesh_agents.sponsor_user_id END,
   sponsor_at = CASE WHEN $7 AND (mesh_agents.sponsor_at < $5 OR (mesh_agents.sponsor_at = $5 AND
                           COALESCE(mesh_agents.sponsor_user_id::text, '') < COALESCE($4::text, '')))
                     THEN $5::timestamptz ELSE mesh_agents.sponsor_at END,
   status = CASE WHEN mesh_agents.state_at <= $5 THEN 'active' ELSE mesh_agents.status END,
   orphaned_at = CASE WHEN mesh_agents.state_at <= $5 THEN NULL ELSE mesh_agents.orphaned_at END,
   state_at = GREATEST(mesh_agents.state_at, $5), updated_at = now()`

// upsertKey merges one key fact. $7 says whether the fact states the label.
const upsertKey = `
INSERT INTO mesh_agent_keys (workspace_id, agent_id, key_id, label, label_at, status, state_at)
VALUES ($1, $2, $3, CASE WHEN $7 THEN left($4,128) ELSE '' END, CASE WHEN $7 THEN $6::timestamptz ELSE 'epoch' END, $5, $6)
ON CONFLICT (workspace_id, agent_id, key_id) DO UPDATE SET
   label = CASE WHEN $7 AND (mesh_agent_keys.label_at < $6 OR (mesh_agent_keys.label_at = $6 AND mesh_agent_keys.label < left($4,128)))
                THEN left($4,128) ELSE mesh_agent_keys.label END,
   label_at = CASE WHEN $7 AND (mesh_agent_keys.label_at < $6 OR (mesh_agent_keys.label_at = $6 AND mesh_agent_keys.label < left($4,128)))
                   THEN $6::timestamptz ELSE mesh_agent_keys.label_at END,
   status = CASE WHEN mesh_agent_keys.state_at < $6 OR (mesh_agent_keys.state_at = $6 AND mesh_agent_keys.status < $5)
                 THEN $5 ELSE mesh_agent_keys.status END,
   orphaned_at = CASE WHEN mesh_agent_keys.state_at < $6 OR (mesh_agent_keys.state_at = $6 AND mesh_agent_keys.status < $5)
                      THEN NULL ELSE mesh_agent_keys.orphaned_at END,
   state_at = GREATEST(mesh_agent_keys.state_at, $6), updated_at = now()`

func applyEvent(ctx context.Context, tx pgx.Tx, ws uuid.UUID, ev Event) error {
	if ev.Type == "task.gate.decided" {
		// Not hierarchy: it carries no data object and must not force a snapshot.
		return nil
	}
	d := ev.Data
	if d == nil || !ev.Timed {
		return markDirty(ctx, tx, ws)
	}
	var err error
	applied := true
	switch ev.Type {
	case "workspace.member.added", "workspace.member.removed":
		if d.UserID == nil {
			applied = false
			break
		}
		status := StatusActive
		if ev.Type == "workspace.member.removed" {
			status = StatusRemoved
		}
		_, err = tx.Exec(ctx, upsertMember, ws, *d.UserID, d.Role, status, ev.At, d.Role != "")
	case "project.created", "project.updated":
		if d.ProjectID == nil {
			applied = false
			break
		}
		_, err = tx.Exec(ctx, upsertProject, ws, *d.ProjectID, d.Slug, d.Name, d.IsArchived != nil && *d.IsArchived, ev.At,
			d.Slug != "", d.Name != "", d.IsArchived != nil)
	case "agent.key.issued", "agent.key.revoked":
		if d.AgentID == nil || d.KeyID == "" {
			applied = false
			break
		}
		if ev.Type == "agent.key.issued" {
			_, err = tx.Exec(ctx, upsertAgent, ws, *d.AgentID, "", d.SponsorUserID, ev.At, false, d.SponsorUserID != nil)
			if err != nil {
				return fmt.Errorf("meshext: apply %s: %w", ev.Type, err)
			}
		}
		status := StatusActive
		if ev.Type == "agent.key.revoked" {
			status = StatusRevoked
		}
		_, err = tx.Exec(ctx, upsertKey, ws, *d.AgentID, d.KeyID, d.Label, status, ev.At, d.Label != "")
	default:
		// task.gate.decided and the like: not hierarchy, nothing to mirror.
	}
	if err != nil {
		return fmt.Errorf("meshext: apply %s: %w", ev.Type, err)
	}
	if !applied {
		return markDirty(ctx, tx, ws)
	}
	return nil
}

// markDirty records that an event could not be applied on its own, so the next
// reconciliation must fetch a full snapshot.
func markDirty(ctx context.Context, tx pgx.Tx, ws uuid.UUID) error {
	if _, err := tx.Exec(ctx, `
INSERT INTO mesh_sync_state (workspace_id, dirty_seq) VALUES ($1, 1)
ON CONFLICT (workspace_id) DO UPDATE SET dirty_seq = mesh_sync_state.dirty_seq + 1`, ws); err != nil {
		return fmt.Errorf("meshext: mark dirty: %w", err)
	}
	return nil
}

// Fetched is the answer to a snapshot request. NotModified means the cursor
// sent was still current.
type Fetched struct {
	NotModified bool
	ETag        string
	Body        []byte
}

// Fetcher gets the workspace hierarchy from Mesh. The implementation holds the
// Mesh actor token (it lives in the plaintext zone); nothing here sees it.
// An error may implement Class() string to name a closed failure class.
type Fetcher interface {
	FetchHierarchy(ctx context.Context, org, workspace uuid.UUID, meshURL, etag string) (Fetched, error)
}

type snapshot struct {
	Workspace struct {
		ID uuid.UUID `json:"id"`
	} `json:"workspace"`
	Projects []struct {
		ID         uuid.UUID `json:"id"`
		Slug       string    `json:"slug"`
		Name       string    `json:"name"`
		IsArchived bool      `json:"is_archived"`
	} `json:"projects"`
	Members []struct {
		UserID uuid.UUID `json:"user_id"`
		Role   string    `json:"role"`
	} `json:"members"`
	Agents []struct {
		ID            uuid.UUID  `json:"id"`
		Slug          string     `json:"slug"`
		SponsorUserID *uuid.UUID `json:"sponsor_user_id"`
		ActiveKeys    []struct {
			KeyID string `json:"key_id"`
			Label string `json:"label"`
		} `json:"active_keys"`
	} `json:"agents"`
}

func (s *snapshot) clean() bool {
	for _, p := range s.Projects {
		if !cleanText(p.Slug, p.Name) {
			return false
		}
	}
	for _, m := range s.Members {
		if !cleanText(m.Role) {
			return false
		}
	}
	for _, a := range s.Agents {
		if !cleanText(a.Slug) {
			return false
		}
		for _, k := range a.ActiveKeys {
			if !cleanText(k.Label) {
				return false
			}
		}
	}
	return true
}

// ReconcileResult is the outcome of one reconciliation.
type ReconcileResult struct {
	// NotModified: Mesh's cursor was unchanged, nothing was read or written.
	NotModified bool
	// Orphaned is how many entities this run newly marked orphaned.
	Orphaned int
}

const maxSnapshotRows = 100000

// FullSyncInterval is how long a reconciliation trusts the ETag cursor after
// the last full snapshot it applied. Past it the next round fetches without
// the cursor, so a divergence on Keep's side is repaired within this time.
const FullSyncInterval = time.Hour

// Reconcile fetches the hierarchy of workspace and makes Keep's mirror match
// it: everything Mesh reports becomes active, everything active that Mesh no
// longer reports becomes orphaned (never deleted). A snapshot never overrides a
// fact newer than the moment the fetch started. Failures are recorded by class
// only; an error never carries the response body.
func (r *Repo) Reconcile(ctx context.Context, f Fetcher, workspace uuid.UUID) (ReconcileResult, error) {
	var (
		org                 uuid.UUID
		meshURL, cursor     string
		dirtySeq, syncedSeq int64
		fullDue             bool
		started             = time.Now().UTC()
	)
	err := r.pool.QueryRow(ctx, `
SELECT i.org_id, i.mesh_url, COALESCE(s.cursor,''), COALESCE(s.dirty_seq,0), COALESCE(s.synced_seq,0),
       s.last_full_sync_at IS NULL OR now() - s.last_full_sync_at >= make_interval(secs => $2)
  FROM mesh_installations i LEFT JOIN mesh_sync_state s ON s.workspace_id = i.workspace_id
 WHERE i.workspace_id = $1`, workspace, FullSyncInterval.Seconds()).Scan(&org, &meshURL, &cursor, &dirtySeq, &syncedSeq, &fullDue)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ReconcileResult{}, ErrNotInstalled
		}
		return ReconcileResult{}, fmt.Errorf("meshext: load sync state: %w", err)
	}
	// The cursor only proves Mesh is unchanged. A full fetch is also due once
	// an interval after the last applied snapshot: it repairs a divergence
	// that exists only on Keep's side, which no 304 would ever report.
	etag := cursor
	if dirtySeq > syncedSeq || fullDue {
		etag = ""
	}
	got, ferr := f.FetchHierarchy(ctx, org, workspace, meshURL, etag)
	if ferr != nil {
		class := errorClass(ferr)
		r.recordFailure(ctx, workspace, class)
		return ReconcileResult{}, &SyncError{class: class}
	}
	if got.NotModified {
		if _, err := r.pool.Exec(ctx, `
INSERT INTO mesh_sync_state (workspace_id, last_sync_at, last_result, last_error_class, synced_seq)
VALUES ($1, now(), 'not_modified', '', $2)
ON CONFLICT (workspace_id) DO UPDATE
   SET last_sync_at = now(), last_result = 'not_modified', last_error_class = '', synced_seq = GREATEST(mesh_sync_state.synced_seq, $2)`,
			workspace, dirtySeq); err != nil {
			return ReconcileResult{}, fmt.Errorf("meshext: record sync: %w", err)
		}
		return ReconcileResult{NotModified: true}, nil
	}
	var snap snapshot
	dec := json.NewDecoder(bytes.NewReader(got.Body))
	if err := dec.Decode(&snap); err != nil || snap.Workspace.ID != workspace ||
		len(snap.Projects)+len(snap.Members)+len(snap.Agents) > maxSnapshotRows {
		r.recordFailure(ctx, workspace, "bad_snapshot")
		return ReconcileResult{}, &SyncError{class: "bad_snapshot"}
	}
	if !snap.clean() {
		r.recordFailure(ctx, workspace, "bad_snapshot")
		return ReconcileResult{}, &SyncError{class: "bad_snapshot"}
	}
	// An ETag that cannot be stored as a cursor is dropped: the next round
	// fetches in full instead of failing.
	cursorOut := strings.Trim(got.ETag, `"`)
	if len(cursorOut) > 128 || !utf8.ValidString(cursorOut) || strings.IndexByte(cursorOut, 0) >= 0 {
		cursorOut = ""
	}
	orphaned, err := r.applySnapshot(ctx, workspace, snap, started, cursorOut, dirtySeq, etag == "")
	if err != nil {
		r.recordFailure(ctx, workspace, "store")
		return ReconcileResult{}, &SyncError{class: "store"}
	}
	return ReconcileResult{Orphaned: orphaned}, nil
}

// SyncError is a failed reconciliation. It names only a closed class: never
// the response, a URL or a credential.
type SyncError struct{ class string }

func (e *SyncError) Error() string { return "meshext: reconcile failed: " + e.class }

// Class is the failure class: unauthorized, not_found, server, network,
// too_large, bad_snapshot, store, or fetch.
func (e *SyncError) Class() string { return e.class }

// ErrNotInstalled is returned for a workspace that is not connected.
var ErrNotInstalled = errors.New("meshext: workspace not connected")

func errorClass(err error) string {
	var c interface{ Class() string }
	if errors.As(err, &c) {
		if s := c.Class(); s != "" && len(s) <= 64 && !strings.ContainsAny(s, " \t\r\n") {
			return s
		}
	}
	return "fetch"
}

func (r *Repo) recordFailure(ctx context.Context, ws uuid.UUID, class string) {
	// Best effort: the failure is already being returned.
	_, _ = r.pool.Exec(ctx, `
INSERT INTO mesh_sync_state (workspace_id, last_sync_at, last_result, last_error_class)
VALUES ($1, now(), 'failed', $2)
ON CONFLICT (workspace_id) DO UPDATE SET last_sync_at = now(), last_result = 'failed', last_error_class = $2`, ws, class)
}

// applySnapshot writes s and the sync state in one transaction. full says the
// snapshot was fetched without a cursor; only then does it count as the full
// fetch that resets the interval of FullSyncInterval.
func (r *Repo) applySnapshot(ctx context.Context, ws uuid.UUID, s snapshot, at time.Time, cursor string, seenSeq int64, full bool) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("meshext: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mesh-sync:' || $1::text, 0))`, ws.String()); err != nil {
		return 0, fmt.Errorf("meshext: lock sync: %w", err)
	}
	orphaned := 0
	count := func(tag interface{ RowsAffected() int64 }, err error) error {
		if err != nil {
			return fmt.Errorf("meshext: apply snapshot: %w", err)
		}
		orphaned += int(tag.RowsAffected())
		return nil
	}

	users := make([]uuid.UUID, 0, len(s.Members))
	for _, m := range s.Members {
		users = append(users, m.UserID)
		role := m.Role
		if role == "" || len(role) > 64 {
			role = "member"
		}
		if _, err := tx.Exec(ctx, upsertMember, ws, m.UserID, role, StatusActive, at, true); err != nil {
			return 0, fmt.Errorf("meshext: apply snapshot: %w", err)
		}
	}
	if err := count(tx.Exec(ctx, `
UPDATE mesh_members SET status = 'orphaned', orphaned_at = $3, state_at = $3, updated_at = now()
 WHERE workspace_id = $1 AND status = 'active' AND state_at <= $3 AND user_id <> ALL($2::uuid[])`, ws, users, at)); err != nil {
		return 0, err
	}

	projects := make([]uuid.UUID, 0, len(s.Projects))
	for _, p := range s.Projects {
		projects = append(projects, p.ID)
		if _, err := tx.Exec(ctx, upsertProject, ws, p.ID, p.Slug, p.Name, p.IsArchived, at, true, true, true); err != nil {
			return 0, fmt.Errorf("meshext: apply snapshot: %w", err)
		}
	}
	if err := count(tx.Exec(ctx, `
UPDATE mesh_projects SET status = 'orphaned', orphaned_at = $3, state_at = $3, updated_at = now()
 WHERE workspace_id = $1 AND status = 'active' AND state_at <= $3 AND project_id <> ALL($2::uuid[])`, ws, projects, at)); err != nil {
		return 0, err
	}

	agents := make([]uuid.UUID, 0, len(s.Agents))
	var keyAgents []uuid.UUID
	var keyIDs []string
	for _, a := range s.Agents {
		agents = append(agents, a.ID)
		if _, err := tx.Exec(ctx, upsertAgent, ws, a.ID, a.Slug, a.SponsorUserID, at, true, true); err != nil {
			return 0, fmt.Errorf("meshext: apply snapshot: %w", err)
		}
		for _, k := range a.ActiveKeys {
			if !ValidEventID(k.KeyID) {
				continue
			}
			keyAgents = append(keyAgents, a.ID)
			keyIDs = append(keyIDs, k.KeyID)
			if _, err := tx.Exec(ctx, upsertKey, ws, a.ID, k.KeyID, k.Label, StatusActive, at, true); err != nil {
				return 0, fmt.Errorf("meshext: apply snapshot: %w", err)
			}
		}
	}
	if err := count(tx.Exec(ctx, `
UPDATE mesh_agents SET status = 'orphaned', orphaned_at = $3, state_at = $3, updated_at = now()
 WHERE workspace_id = $1 AND status = 'active' AND state_at <= $3 AND agent_id <> ALL($2::uuid[])`, ws, agents, at)); err != nil {
		return 0, err
	}
	if err := count(tx.Exec(ctx, `
UPDATE mesh_agent_keys k SET status = 'orphaned', orphaned_at = $4, state_at = $4, updated_at = now()
 WHERE k.workspace_id = $1 AND k.status = 'active' AND k.state_at <= $4
   AND NOT EXISTS (SELECT 1 FROM unnest($2::uuid[], $3::text[]) AS s(a, kid) WHERE s.a = k.agent_id AND s.kid = k.key_id)`,
		ws, keyAgents, keyIDs, at)); err != nil {
		return 0, err
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO mesh_sync_state (workspace_id, cursor, synced_seq, last_sync_at, last_result, last_error_class, orphaned_count, last_full_sync_at)
VALUES ($1, $2, $3, now(), 'ok', '', $4, CASE WHEN $5::bool THEN now() END)
ON CONFLICT (workspace_id) DO UPDATE
   SET cursor = $2, synced_seq = GREATEST(mesh_sync_state.synced_seq, $3), last_sync_at = now(),
       last_result = 'ok', last_error_class = '', orphaned_count = $4,
       last_full_sync_at = CASE WHEN $5::bool THEN now() ELSE mesh_sync_state.last_full_sync_at END`, ws, cursor, seenSeq, orphaned, full); err != nil {
		return 0, fmt.Errorf("meshext: record sync: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("meshext: commit snapshot: %w", err)
	}
	return orphaned, nil
}

// ReconcileAll reconciles every workspace connected as an extension once. A
// store-only installation has no Keep extension in its Mesh, so it is never
// fetched. A failure of one does not stop the others. Newly orphaned entities
// raise a warning, the alert the tenancy model asks for.
func (r *Repo) ReconcileAll(ctx context.Context, f Fetcher, log *slog.Logger) {
	rows, err := r.pool.Query(ctx, `SELECT workspace_id FROM mesh_installations WHERE mode = $1 ORDER BY workspace_id`, string(ModeExtension))
	if err != nil {
		log.Error("mesh reconcile: list installations", "action", "mesh.reconcile", "error_class", "store")
		return
	}
	var all []uuid.UUID
	for rows.Next() {
		var ws uuid.UUID
		if rows.Scan(&ws) == nil {
			all = append(all, ws)
		}
	}
	rows.Close()
	for _, ws := range all {
		res, err := r.Reconcile(ctx, f, ws)
		switch {
		case err != nil:
			log.Warn("mesh reconcile failed", "action", "mesh.reconcile", "workspace_id", ws.String(), "error_class", errorClass(err))
		case res.Orphaned > 0:
			log.Warn("mesh entities orphaned", "action", "mesh.orphaned", "workspace_id", ws.String())
		}
	}
}
