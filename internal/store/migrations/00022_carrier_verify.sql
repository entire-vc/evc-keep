-- +goose Up
-- Server-side carrier verification. A verify request fans out into one signed
-- verify job per carrier, queued in deployment_jobs like any other job, and
-- this table pair records what each runner reported. Metadata only: a state,
-- a fingerprint and a timestamp per carrier; no value and no file content.
ALTER TABLE carriers ADD CONSTRAINT carriers_org_id_id_unique UNIQUE (org_id,id);

-- A verify job never writes and never needs the value, so it must not count
-- against the hourly deploy allowance of its (secret, runner) pair.
ALTER TABLE deployment_jobs
    ADD COLUMN action TEXT NOT NULL DEFAULT 'deploy' CHECK (action = 'deploy' OR action = 'exec' OR action = 'verify');

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION keep_deployment_job_frozen() RETURNS trigger AS $$
BEGIN
    IF ROW(OLD.action,OLD.id,OLD.org_id,OLD.runner_id,OLD.deployment_request_id,OLD.request_id,
           OLD.secret_id,OLD.version_id,OLD.secret_scope_level,OLD.secret_scope_id,
           OLD.store_id,OLD.store_owner_scope_level,OLD.store_owner_scope_id,
           OLD.provider,OLD.provider_ref,OLD.provider_version,OLD.catalog_name,
           OLD.catalog_class,OLD.job_payload,OLD.nonce,OLD.expires_at,OLD.created_at)
       IS DISTINCT FROM
       ROW(NEW.action,NEW.id,NEW.org_id,NEW.runner_id,NEW.deployment_request_id,NEW.request_id,
           NEW.secret_id,NEW.version_id,NEW.secret_scope_level,NEW.secret_scope_id,
           NEW.store_id,NEW.store_owner_scope_level,NEW.store_owner_scope_id,
           NEW.provider,NEW.provider_ref,NEW.provider_version,NEW.catalog_name,
           NEW.catalog_class,NEW.job_payload,NEW.nonce,NEW.expires_at,NEW.created_at) THEN
        RAISE EXCEPTION 'deployment job metadata is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TABLE carrier_verifications (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    request_id TEXT NOT NULL CHECK (request_id ~ '^[A-Za-z0-9-]{1,36}$'),
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    secret_id UUID NOT NULL,
    secret_scope_level TEXT NOT NULL CHECK (secret_scope_level IN ('org','ws','proj','user')),
    secret_scope_id UUID NOT NULL,
    expected_version TEXT NOT NULL,
    expected_fingerprint TEXT NOT NULL CHECK (expected_fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id,id),
    UNIQUE (org_id,request_id),
    FOREIGN KEY (org_id,secret_id) REFERENCES secrets(org_id,id)
);

CREATE TABLE carrier_verification_items (
    verification_id UUID NOT NULL,
    org_id UUID NOT NULL,
    carrier_id UUID NOT NULL,
    runner_id UUID,
    job_id UUID,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','match','mismatch','unreachable','failed')),
    error_class TEXT NOT NULL DEFAULT '' CHECK (error_class ~ '^[a-z_]{0,32}$'),
    observed_fingerprint TEXT CHECK (observed_fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (verification_id,carrier_id),
    FOREIGN KEY (org_id,verification_id) REFERENCES carrier_verifications(org_id,id) ON DELETE CASCADE,
    FOREIGN KEY (org_id,carrier_id) REFERENCES carriers(org_id,id) ON DELETE CASCADE,
    FOREIGN KEY (org_id,job_id) REFERENCES deployment_jobs(org_id,id),
    CHECK ((state = 'pending') = (completed_at IS NULL)),
    CHECK ((job_id IS NULL) = (runner_id IS NULL))
);
CREATE UNIQUE INDEX carrier_verification_items_job_idx ON carrier_verification_items(org_id,job_id)
    WHERE job_id IS NOT NULL;

ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided','carrier.verify'));

-- +goose Down
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided')) NOT VALID;
DROP TABLE carrier_verification_items;
DROP TABLE carrier_verifications;
-- Verify jobs and their request rows cannot outlive the action column that
-- tells them apart from deployments.
WITH gone AS (DELETE FROM deployment_jobs WHERE action = 'verify' RETURNING org_id, deployment_request_id)
DELETE FROM deployment_requests r USING gone g WHERE r.org_id = g.org_id AND r.id = g.deployment_request_id;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION keep_deployment_job_frozen() RETURNS trigger AS $$
BEGIN
    IF ROW(OLD.id,OLD.org_id,OLD.runner_id,OLD.deployment_request_id,OLD.request_id,
           OLD.secret_id,OLD.version_id,OLD.secret_scope_level,OLD.secret_scope_id,
           OLD.store_id,OLD.store_owner_scope_level,OLD.store_owner_scope_id,
           OLD.provider,OLD.provider_ref,OLD.provider_version,OLD.catalog_name,
           OLD.catalog_class,OLD.job_payload,OLD.nonce,OLD.expires_at,OLD.created_at)
       IS DISTINCT FROM
       ROW(NEW.id,NEW.org_id,NEW.runner_id,NEW.deployment_request_id,NEW.request_id,
           NEW.secret_id,NEW.version_id,NEW.secret_scope_level,NEW.secret_scope_id,
           NEW.store_id,NEW.store_owner_scope_level,NEW.store_owner_scope_id,
           NEW.provider,NEW.provider_ref,NEW.provider_version,NEW.catalog_name,
           NEW.catalog_class,NEW.job_payload,NEW.nonce,NEW.expires_at,NEW.created_at) THEN
        RAISE EXCEPTION 'deployment job metadata is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
ALTER TABLE deployment_jobs DROP COLUMN action;
ALTER TABLE carriers DROP CONSTRAINT carriers_org_id_id_unique;
