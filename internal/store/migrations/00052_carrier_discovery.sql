-- +goose Up
-- Carrier discovery. A discover job names a store and a runner and nothing
-- else; the runner's own host policy decides what it may read. The report is
-- path, variable name, keyed fingerprint and length per finding: never a
-- value, never file content. An unknown carrier opens an incident here; it
-- never queues a rotation or deploy job.
CREATE TABLE discovery_jobs (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    runner_id UUID NOT NULL,
    request_id TEXT NOT NULL CHECK (request_id ~ '^[A-Za-z0-9-]{1,36}$'),
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    store_id UUID NOT NULL,
    job_payload BYTEA NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 16),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','issued','completed','failed','expired')),
    issued_at TIMESTAMPTZ,
    material_issued_at TIMESTAMPTZ,
    result JSONB,
    UNIQUE (org_id,id),
    UNIQUE (org_id,request_id),
    UNIQUE (org_id,runner_id,nonce),
    FOREIGN KEY (org_id,runner_id) REFERENCES runners(org_id,id),
    FOREIGN KEY (org_id,store_id) REFERENCES stores(org_id,id),
    CHECK (expires_at > created_at),
    CHECK (status <> 'queued' OR issued_at IS NULL),
    CHECK (status NOT IN ('issued','completed','failed') OR issued_at IS NOT NULL),
    CHECK (material_issued_at IS NULL OR issued_at IS NOT NULL),
    CHECK ((result IS NOT NULL) = (status IN ('completed','failed')))
);
-- One discover at a time per runner.
CREATE UNIQUE INDEX discovery_jobs_one_active ON discovery_jobs(org_id,runner_id)
    WHERE status IN ('queued','issued');
CREATE INDEX discovery_jobs_pull_idx ON discovery_jobs(org_id,runner_id,created_at,id)
    WHERE status='queued';
CREATE INDEX discovery_jobs_rate_idx ON discovery_jobs(org_id,runner_id,created_at);

-- Transport may change only lifecycle columns; the signed payload is frozen.
-- +goose StatementBegin
CREATE FUNCTION keep_discovery_job_frozen() RETURNS trigger AS $$
BEGIN
    IF ROW(OLD.id,OLD.org_id,OLD.runner_id,OLD.request_id,OLD.request_hash,OLD.store_id,
           OLD.job_payload,OLD.nonce,OLD.expires_at,OLD.created_at)
       IS DISTINCT FROM
       ROW(NEW.id,NEW.org_id,NEW.runner_id,NEW.request_id,NEW.request_hash,NEW.store_id,
           NEW.job_payload,NEW.nonce,NEW.expires_at,NEW.created_at) THEN
        RAISE EXCEPTION 'discovery job metadata is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER discovery_jobs_frozen BEFORE UPDATE ON discovery_jobs
    FOR EACH ROW EXECUTE FUNCTION keep_discovery_job_frozen();

-- One row per finding of a completed scan, plus one per known carrier the
-- scan did not find. incident_state is set only for the verdicts that need a
-- person to look: an unregistered carrier (sprawl) and a registered one that
-- was not found (unknown_find).
CREATE TABLE discovery_observations (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    job_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('match','stale','sprawl','unknown_find')),
    carrier_id UUID,
    -- An unknown_find line carries a registered carrier's path and field, so
    -- both are bounded as registration bounds them (characters, no control).
    path TEXT NOT NULL CHECK (path <> '' AND char_length(path) <= 4096 AND path !~ '[[:cntrl:]]'),
    name TEXT NOT NULL CHECK (name <> '' AND char_length(name) <= 256 AND name !~ '[[:cntrl:]]'),
    fingerprint TEXT NOT NULL CHECK (fingerprint = '' OR fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    length INTEGER NOT NULL CHECK (length >= 0),
    incident_state TEXT CHECK (incident_state IN ('open')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id,job_id) REFERENCES discovery_jobs(org_id,id),
    FOREIGN KEY (org_id,carrier_id) REFERENCES carriers(org_id,id),
    CHECK (incident_state IS NULL OR verdict IN ('sprawl','unknown_find')),
    CHECK (verdict <> 'unknown_find' OR (fingerprint = '' AND length = 0)),
    CHECK (verdict = 'sprawl' OR carrier_id IS NOT NULL)
);
CREATE INDEX discovery_observations_incident_idx ON discovery_observations(org_id,created_at,id)
    WHERE incident_state='open';

ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.requested','org.key_level.changed',
                     'org.key_level.change_denied','org.key_level.change_failed',
                     'identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided','carrier.verify','mesh.install',
                     'secret.rotate','mesh.secret.put','mesh.secret.resolve','org.bootstrap','mesh.install.pending',
                     'store.bind_default','deploy.policy_set','mesh.token','mesh.uninstall','mesh.secret.metadata','transfer.imported','carrier.discover'));

-- +goose Down
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.requested','org.key_level.changed',
                     'org.key_level.change_denied','org.key_level.change_failed',
                     'identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided','carrier.verify','mesh.install',
                     'secret.rotate','mesh.secret.put','mesh.secret.resolve','org.bootstrap','mesh.install.pending',
                     'store.bind_default','deploy.policy_set','mesh.token','mesh.uninstall','mesh.secret.metadata',
                     'transfer.imported')) NOT VALID;
DROP TABLE discovery_observations;
DROP TRIGGER discovery_jobs_frozen ON discovery_jobs;
DROP FUNCTION keep_discovery_job_frozen();
DROP TABLE discovery_jobs;
