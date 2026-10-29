-- +goose Up
-- Deployment policy, approval and queue contain metadata only. The target is
-- frozen as JSONB and hashed with the secret/runner binding; no value or
-- provider response is accepted by these tables.
CREATE TABLE deployment_policies (
    org_id UUID PRIMARY KEY REFERENCES organizations(id),
    rules JSONB NOT NULL DEFAULT '{"rules":[]}'::jsonb,
    max_deploys_per_hour INTEGER NOT NULL DEFAULT 10
        CHECK (max_deploys_per_hour BETWEEN 1 AND 1000),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0)
);

ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_org_secret_id_unique
    UNIQUE (org_id,secret_id,id);

CREATE TABLE deployment_requests (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    request_id TEXT NOT NULL CHECK (request_id ~ '^[A-Za-z0-9-]{1,36}$'),
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    target_key BYTEA NOT NULL CHECK (octet_length(target_key) = 32),
    secret_id UUID NOT NULL,
    version_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    secret_scope_level TEXT NOT NULL CHECK (secret_scope_level IN ('org','ws','proj','user')),
    secret_scope_id UUID NOT NULL,
    target JSONB NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('queued','approval_required','denied','rate_limited','unsupported_provider')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id,id),
    UNIQUE (org_id,request_id),
    FOREIGN KEY (org_id,secret_id) REFERENCES secrets(org_id,id),
    FOREIGN KEY (org_id,runner_id) REFERENCES runners(org_id,id),
    FOREIGN KEY (org_id,secret_id,version_id) REFERENCES secret_versions(org_id,secret_id,id)
);

CREATE TABLE approval_requests (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    deployment_request_id UUID NOT NULL,
    binding_hash BYTEA NOT NULL CHECK (octet_length(binding_hash) = 32),
    target_key BYTEA NOT NULL CHECK (octet_length(target_key) = 32),
    status TEXT NOT NULL DEFAULT 'requested' CHECK (status IN ('requested','approved','rejected')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by UUID,
    decided_at TIMESTAMPTZ,
    UNIQUE (org_id,id),
    UNIQUE (org_id,deployment_request_id),
    FOREIGN KEY (org_id,deployment_request_id) REFERENCES deployment_requests(org_id,id),
    FOREIGN KEY (org_id,decided_by) REFERENCES users(org_id,id),
    CHECK ((status='requested') = (decided_at IS NULL)),
    CHECK ((decided_by IS NULL) = (decided_at IS NULL))
);
CREATE INDEX approval_requests_target_idx ON approval_requests(org_id,target_key)
    WHERE status='approved';

CREATE TABLE deployment_jobs (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    runner_id UUID NOT NULL,
    deployment_request_id UUID NOT NULL,
    request_id TEXT NOT NULL,
    secret_id UUID NOT NULL,
    version_id UUID NOT NULL,
    secret_scope_level TEXT NOT NULL CHECK (secret_scope_level IN ('org','ws','proj','user')),
    secret_scope_id UUID NOT NULL,
    store_id UUID NOT NULL,
    store_owner_scope_level TEXT NOT NULL CHECK (store_owner_scope_level IN ('org','ws','proj','user')),
    store_owner_scope_id UUID NOT NULL,
    provider TEXT NOT NULL,
    provider_ref TEXT NOT NULL,
    provider_version TEXT NOT NULL,
    catalog_name TEXT NOT NULL,
    catalog_class TEXT NOT NULL,
    job_payload BYTEA NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce)=16),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','issued','completed','failed','expired')),
    issued_at TIMESTAMPTZ,
    material_issued_at TIMESTAMPTZ,
    result JSONB,
    UNIQUE (org_id,id),
    UNIQUE (org_id,deployment_request_id),
    UNIQUE (org_id,runner_id,nonce),
    FOREIGN KEY (org_id,deployment_request_id) REFERENCES deployment_requests(org_id,id),
    FOREIGN KEY (org_id,runner_id) REFERENCES runners(org_id,id),
    FOREIGN KEY (org_id,secret_id,version_id) REFERENCES secret_versions(org_id,secret_id,id),
    FOREIGN KEY (org_id,store_id) REFERENCES stores(org_id,id),
    CHECK (expires_at > created_at),
    CHECK (status <> 'queued' OR issued_at IS NULL),
    CHECK (status NOT IN ('issued','completed','failed') OR issued_at IS NOT NULL),
    CHECK (material_issued_at IS NULL OR issued_at IS NOT NULL),
    CHECK ((result IS NOT NULL) = (status IN ('completed','failed')))
);
CREATE INDEX deployment_jobs_pull_idx ON deployment_jobs(org_id,runner_id,created_at,id)
    WHERE status='queued';
CREATE INDEX deployment_jobs_rate_idx ON deployment_jobs(org_id,secret_id,runner_id,created_at);

-- Transport may change only lifecycle columns. It signs job_payload at pull
-- time; replacing the payload or its resolver snapshots would make policy
-- approve one job while the runner executes another.
-- +goose StatementBegin
CREATE FUNCTION keep_deployment_job_frozen() RETURNS trigger AS $$
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
CREATE TRIGGER deployment_jobs_frozen BEFORE UPDATE ON deployment_jobs
    FOR EACH ROW EXECUTE FUNCTION keep_deployment_job_frozen();

ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision'));

-- +goose Down
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired')) NOT VALID;
DROP TABLE deployment_jobs;
DROP FUNCTION keep_deployment_job_frozen();
DROP TABLE approval_requests;
DROP TABLE deployment_requests;
DROP TABLE deployment_policies;
ALTER TABLE secret_versions DROP CONSTRAINT secret_versions_org_secret_id_unique;
