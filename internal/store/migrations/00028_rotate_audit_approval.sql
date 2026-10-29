-- +goose Up
-- Rotation in the journal and behind a human approval. Metadata only: ids,
-- names, version labels, a fingerprint, a length and closed classes.

-- The journal's closed action registry gains the rotate action.
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided','carrier.verify','mesh.install',
                     'secret.rotate'));

-- Length of the new value, a byte count the journal records; 0 is unknown.
ALTER TABLE rotation_runs ADD COLUMN new_length INTEGER NOT NULL DEFAULT 0 CHECK (new_length >= 0);
ALTER TABLE rotation_keys ADD COLUMN new_length INTEGER NOT NULL DEFAULT 0 CHECK (new_length >= 0);

-- An approval is for a deployment request or for a rotation of one secret,
-- never both. A rotation approval names the run id the approval will create;
-- the run row exists only after a human approves.
ALTER TABLE approval_requests
    ALTER COLUMN deployment_request_id DROP NOT NULL,
    ADD COLUMN rotation_secret_id UUID,
    ADD COLUMN rotation_run_id UUID,
    ADD CONSTRAINT approval_requests_subject_one CHECK (
        (deployment_request_id IS NOT NULL AND rotation_secret_id IS NULL AND rotation_run_id IS NULL)
     OR (deployment_request_id IS NULL AND rotation_secret_id IS NOT NULL AND rotation_run_id IS NOT NULL)),
    ADD CONSTRAINT approval_requests_rotation_run_unique UNIQUE (org_id, rotation_run_id);
CREATE INDEX approval_requests_rotation_secret_idx ON approval_requests(org_id, rotation_secret_id)
    WHERE rotation_secret_id IS NOT NULL;

-- The frozen-content trigger covers the new columns too.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION keep_approval_frozen() RETURNS trigger AS $$
BEGIN
    IF ROW(OLD.id,OLD.org_id,OLD.deployment_request_id,OLD.binding_hash,OLD.target_key,OLD.requested_at,
           OLD.requester_type,OLD.requester_id,OLD.requester_sponsor_id,OLD.requester_via,OLD.expires_at,
           OLD.rotation_secret_id,OLD.rotation_run_id)
       IS DISTINCT FROM
       ROW(NEW.id,NEW.org_id,NEW.deployment_request_id,NEW.binding_hash,NEW.target_key,NEW.requested_at,
           NEW.requester_type,NEW.requester_id,NEW.requester_sponsor_id,NEW.requester_via,NEW.expires_at,
           NEW.rotation_secret_id,NEW.rotation_run_id) THEN
        RAISE EXCEPTION 'approval request content is immutable';
    END IF;
    IF OLD.status <> 'requested' THEN
        RAISE EXCEPTION 'approval request already decided';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- Rotation approvals cannot exist in the older schema and are removed.
-- Journal rows of the rotate action stay (append-only) and remain verifiable;
-- the older CHECK is NOT VALID, so it only refuses new inserts.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION keep_approval_frozen() RETURNS trigger AS $$
BEGIN
    IF ROW(OLD.id,OLD.org_id,OLD.deployment_request_id,OLD.binding_hash,OLD.target_key,OLD.requested_at,
           OLD.requester_type,OLD.requester_id,OLD.requester_sponsor_id,OLD.requester_via,OLD.expires_at)
       IS DISTINCT FROM
       ROW(NEW.id,NEW.org_id,NEW.deployment_request_id,NEW.binding_hash,NEW.target_key,NEW.requested_at,
           NEW.requester_type,NEW.requester_id,NEW.requester_sponsor_id,NEW.requester_via,NEW.expires_at) THEN
        RAISE EXCEPTION 'approval request content is immutable';
    END IF;
    IF OLD.status <> 'requested' THEN
        RAISE EXCEPTION 'approval request already decided';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
DROP INDEX approval_requests_rotation_secret_idx;
DELETE FROM approval_requests WHERE rotation_run_id IS NOT NULL;
ALTER TABLE approval_requests
    DROP CONSTRAINT approval_requests_rotation_run_unique,
    DROP CONSTRAINT approval_requests_subject_one,
    DROP COLUMN rotation_run_id,
    DROP COLUMN rotation_secret_id,
    ALTER COLUMN deployment_request_id SET NOT NULL;
ALTER TABLE rotation_keys DROP COLUMN new_length;
ALTER TABLE rotation_runs DROP COLUMN new_length;
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided','carrier.verify','mesh.install')) NOT VALID;
