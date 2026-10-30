-- +goose Up
-- An installation is either a Mesh extension (Keep calls Mesh with the actor
-- token: hierarchy sync, gate cards) or only a secret store (Mesh calls Keep
-- through its MESH_KEEP_* settings and no Keep extension exists in that Mesh).
-- Keep calls Mesh only for an extension. The mode is explicit, never derived
-- from a missing token: an extension whose token delivery broke must keep
-- failing its reconciliation loudly.
ALTER TABLE mesh_installations ADD COLUMN mode TEXT NOT NULL DEFAULT 'extension'
    CHECK (mode IN ('store','extension'));

-- One-off backfill: an installation that never had a token delivered and never
-- reconciled successfully has never worked as an extension.
UPDATE mesh_installations i SET mode = 'store'
 WHERE i.token_signed_at IS NULL
   AND NOT EXISTS (SELECT 1 FROM mesh_sync_state s
                    WHERE s.workspace_id = i.workspace_id
                      AND (s.last_full_sync_at IS NOT NULL OR s.last_result IN ('ok','not_modified')));

-- +goose Down
ALTER TABLE mesh_installations DROP COLUMN mode;
