-- +goose Up
-- The provider key that stood behind the old version when the run began, if the
-- provider could name it. Empty: unknown. Metadata only: an id, never a value.
ALTER TABLE rotation_keys ADD COLUMN original_key_id TEXT NOT NULL DEFAULT ''
    CHECK (original_key_id = '' OR original_key_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');

-- +goose Down
ALTER TABLE rotation_keys DROP COLUMN original_key_id;
