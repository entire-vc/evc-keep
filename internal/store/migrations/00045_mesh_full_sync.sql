-- +goose Up
-- The ETag cursor only says whether Mesh changed. A divergence that exists
-- only in Keep's mirror (a row edited by hand, a write bug, a partial restore)
-- survives every 304, so a reconciliation also fetches without the cursor once
-- this long after the last full snapshot it applied. NULL means none yet.
ALTER TABLE mesh_sync_state ADD COLUMN last_full_sync_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE mesh_sync_state DROP COLUMN last_full_sync_at;
