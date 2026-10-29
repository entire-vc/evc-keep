-- +goose Up
-- Which provider key stands behind which version of a secret, per rotation
-- run. Metadata only: ids, version labels and a fingerprint, never a value.
CREATE TABLE rotation_keys (
    run_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    secret_id UUID NOT NULL,
    key_id TEXT NOT NULL CHECK (key_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    old_version TEXT NOT NULL DEFAULT '' CHECK (char_length(old_version) <= 128),
    new_version TEXT NOT NULL CHECK (char_length(new_version) BETWEEN 1 AND 128),
    fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX rotation_keys_version_idx ON rotation_keys(org_id, secret_id, new_version);

-- +goose Down
DROP TABLE rotation_keys;
