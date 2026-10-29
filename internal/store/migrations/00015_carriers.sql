-- +goose Up
-- Carrier metadata only. Composite foreign keys bind both the secret and
-- its deployed version to the authenticated organization.
CREATE TABLE carriers (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    secret_id UUID NOT NULL,
    version TEXT NOT NULL,
    host TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_path TEXT NOT NULL,
    target_field TEXT NOT NULL DEFAULT '',
    consumer TEXT NOT NULL DEFAULT '',
    healthcheck_ref TEXT NOT NULL DEFAULT '',
    last_fp TEXT NOT NULL CHECK (last_fp ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    state TEXT NOT NULL CHECK (state IN ('registered', 'stale', 'unknown')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified_at TIMESTAMPTZ,
    FOREIGN KEY (org_id, secret_id) REFERENCES secrets(org_id, id),
    FOREIGN KEY (org_id, secret_id, version)
        REFERENCES secret_versions(org_id, secret_id, provider_version),
    UNIQUE (org_id, secret_id, host, target_kind, target_path, target_field)
);

-- +goose Down
DROP TABLE carriers;
