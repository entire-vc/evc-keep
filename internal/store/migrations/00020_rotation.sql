-- +goose Up
-- Two-phase rotation runs. Metadata only: ids, version labels, state names,
-- fingerprints and closed error classes. No value, ciphertext or provider
-- text is ever stored here.
CREATE TABLE rotation_runs (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    secret_id UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('new_version','deploying','verifying','revoking_old','done','failed')),
    old_version TEXT NOT NULL DEFAULT '' CHECK (char_length(old_version) <= 128),
    new_version TEXT NOT NULL DEFAULT '' CHECK (char_length(new_version) <= 128),
    expected_fp TEXT NOT NULL DEFAULT '' CHECK (expected_fp = '' OR expected_fp ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    error_class TEXT NOT NULL DEFAULT '' CHECK (error_class IN ('','no_carriers','deploy_failed','fingerprint_mismatch','unhealthy','verify_failed','revoke_failed','prepare_failed')),
    incident_opened BOOLEAN NOT NULL DEFAULT false,
    lease_owner TEXT NOT NULL DEFAULT '' CHECK (char_length(lease_owner) <= 64),
    lease_until TIMESTAMPTZ,
    -- Fencing token: grows with every claim; collaborators refuse a lower one.
    lease_epoch BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- One active run per secret: the database is the lock.
CREATE UNIQUE INDEX rotation_runs_one_active_idx ON rotation_runs(org_id, secret_id)
    WHERE state NOT IN ('done','failed');

CREATE TABLE rotation_steps (
    run_id UUID NOT NULL REFERENCES rotation_runs(id) ON DELETE CASCADE,
    carrier_id TEXT NOT NULL CHECK (char_length(carrier_id) BETWEEN 1 AND 64),
    deploy_state TEXT NOT NULL DEFAULT 'pending' CHECK (deploy_state IN ('pending','ok','failed')),
    verify_state TEXT NOT NULL DEFAULT 'pending' CHECK (verify_state IN ('pending','ok','failed')),
    observed_fp TEXT NOT NULL DEFAULT '' CHECK (observed_fp = '' OR observed_fp ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    error_class TEXT NOT NULL DEFAULT '' CHECK (error_class IN ('','deploy_failed','fingerprint_mismatch','unhealthy','verify_failed')),
    PRIMARY KEY (run_id, carrier_id)
);

-- +goose Down
DROP TABLE rotation_steps;
DROP TABLE rotation_runs;
