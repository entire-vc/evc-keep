package meshext

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Settings is the part of the Keep extension's workspace settings that Keep
// applies. Mesh sends a full snapshot of the non-secret workspace settings with
// every install handshake (field "settings"); Keep keeps only the keys below
// and reads no other key, so a value Mesh should not have sent is dropped
// unread.
type Settings struct {
	// ApprovalsViaMesh is nil when the snapshot does not carry the key: the
	// manifest default, true, applies.
	ApprovalsViaMesh *bool
}

// ErrInvalidSettings is a settings snapshot that is not a JSON object, or
// whose approvals_via_mesh is not a boolean. The error names no value.
var ErrInvalidSettings = errors.New("meshext: invalid workspace settings")

// ParseSettings reads the settings field of a handshake body. present is false
// when the field is absent (a Mesh that does not send settings): the
// stored setting is then left as it is.
func ParseSettings(raw json.RawMessage) (s Settings, present bool, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return Settings{}, false, nil
	}
	if trimmed[0] != '{' {
		return Settings{}, false, ErrInvalidSettings
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(trimmed, &obj) != nil {
		return Settings{}, false, ErrInvalidSettings
	}
	if v, ok := obj["approvals_via_mesh"]; ok {
		var b bool
		if json.Unmarshal(v, &b) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return Settings{}, false, ErrInvalidSettings
		}
		s.ApprovalsViaMesh = &b
	}
	return s, true, nil
}

// Snapshot is the settings snapshot of one authenticated handshake: what it
// carries, when Mesh signed it, and how a change it makes is journaled.
type Snapshot struct {
	Settings Settings
	// SignedAt is the handshake's X-Mesh-Timestamp in Unix seconds, after
	// the signature and the skew window were checked.
	SignedAt int64
	// Journal appends the record of a change of the stored setting in tx,
	// the transaction that makes the change (threat model §4.2.3). It runs
	// only when the stored value really changes and receives the
	// organisation that holds the workspace and only the new settings; its
	// error rolls the change back. A nil Journal is refused
	// before anything is written: no change goes unjournaled.
	Journal func(ctx context.Context, tx pgx.Tx, org uuid.UUID, s Settings) error
}

// ErrNoSettingsJournal is a snapshot handed over without its journal.
var ErrNoSettingsJournal = errors.New("meshext: settings snapshot without a journal")

// ErrSettingsJournal wraps the error of a Snapshot's Journal: the change was
// rolled back with everything else of its transaction.
var ErrSettingsJournal = errors.New("meshext: settings change not journaled")

// SetSettings applies the settings snapshot s of workspace held by org. The
// caller has authenticated the handshake that carried it and holds the
// workspace lock. A snapshot signed before the last applied one changes
// nothing; an unchanged value writes no journal record.
func (r *Repo) SetSettings(ctx context.Context, workspace, org uuid.UUID, s Snapshot) error {
	if s.Journal == nil {
		return ErrNoSettingsJournal
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("meshext: record workspace settings: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := applySettings(ctx, tx, workspace, org, s); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("meshext: record workspace settings: %w", err)
	}
	return nil
}

// settingsSQL applies a snapshot only if it was signed at or after the last
// applied one. The signed time moves even when the value stays the same, so
// an older opposite snapshot arriving after an equal newer one loses too.
const settingsSQL = `UPDATE mesh_installations SET approvals_via_mesh = $3, settings_signed_at = $4
 WHERE workspace_id = $1 AND org_id = $2 AND (settings_signed_at IS NULL OR $4 >= settings_signed_at)`

// applySettings applies s in tx and journals a change of the stored value in
// the same transaction. Whether the value changed is read from the row as it
// was before the update (locked FOR UPDATE), not from the number of updated
// rows: the update also moves the signed time of an equal value.
func applySettings(ctx context.Context, tx pgx.Tx, workspace, org uuid.UUID, s Snapshot) error {
	var prev *bool
	err := tx.QueryRow(ctx, `SELECT approvals_via_mesh FROM mesh_installations
 WHERE workspace_id = $1 AND org_id = $2 FOR UPDATE`, workspace, org).Scan(&prev)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("meshext: read workspace settings: %w", err)
	}
	tag, err := tx.Exec(ctx, settingsSQL, workspace, org, s.Settings.ApprovalsViaMesh, s.SignedAt)
	if err != nil {
		return fmt.Errorf("meshext: record workspace settings: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return nil // signed before the last applied snapshot
	}
	if sameSetting(prev, s.Settings.ApprovalsViaMesh) {
		return nil
	}
	if err := s.Journal(ctx, tx, org, s.Settings); err != nil {
		return fmt.Errorf("%w: %w", ErrSettingsJournal, err)
	}
	return nil
}

// sameSetting is SQL's NOT (a IS DISTINCT FROM b) for a nullable boolean.
func sameSetting(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Binding and upgrading publish the setting in the transaction that makes
// the extension visible, so no concurrent approval sees a default true in
// place of a false snapshot. With an older Mesh there is no snapshot to apply.
func setBindingSettings(ctx context.Context, tx pgx.Tx, workspace, org uuid.UUID, snapshots []Snapshot) error {
	for _, s := range snapshots {
		if s.Journal == nil {
			return ErrNoSettingsJournal
		}
		if err := applySettings(ctx, tx, workspace, org, s); err != nil {
			return fmt.Errorf("meshext: record binding settings: %w", err)
		}
	}
	return nil
}
