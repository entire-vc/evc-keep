-- +goose Up
-- A rotation run's intent to ask the provider for a key, written before the
-- Issue that cannot be undone. A run that finds its intent and no key row does
-- not know whether the key was issued, and never asks again. Metadata only.
CREATE TABLE rotation_intents (
    run_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    secret_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE rotation_intents;
