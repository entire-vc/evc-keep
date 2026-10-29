-- +goose Up
-- Human approval of a deployment request. The approval binds to the
-- canonical request hash computed in internal/deployment; the requester is
-- stored so the hash can be recomputed from the frozen row at decision time
-- and so a human is never allowed to approve their own request. Metadata
-- only: no value, ciphertext or provider text lives in these tables.
ALTER TABLE approval_requests
    ADD COLUMN requester_type TEXT NOT NULL DEFAULT '' CHECK (requester_type IN ('','agent','user','service')),
    ADD COLUMN requester_id TEXT NOT NULL DEFAULT '' CHECK (char_length(requester_id) <= 64),
    ADD COLUMN requester_sponsor_id TEXT NOT NULL DEFAULT '' CHECK (char_length(requester_sponsor_id) <= 64),
    ADD COLUMN requester_via TEXT NOT NULL DEFAULT '' CHECK (requester_via IN ('','api','cli','mcp','mesh-plugin','console')),
    ADD COLUMN expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '24 hours'),
    ADD COLUMN decision_reason TEXT NOT NULL DEFAULT '' CHECK (char_length(decision_reason) <= 200);
CREATE INDEX approval_requests_org_status_idx ON approval_requests(org_id,status,requested_at DESC);

-- The decision is the only thing that may change on an approval, and only once.
-- +goose StatementBegin
CREATE FUNCTION keep_approval_frozen() RETURNS trigger AS $$
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
CREATE TRIGGER approval_requests_frozen BEFORE UPDATE ON approval_requests
    FOR EACH ROW EXECUTE FUNCTION keep_approval_frozen();

-- What a human was shown is what runs: the frozen request cannot be edited
-- after it is stored.
-- +goose StatementBegin
CREATE FUNCTION keep_deployment_request_frozen() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'deployment request is immutable';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER deployment_requests_frozen BEFORE UPDATE ON deployment_requests
    FOR EACH ROW EXECUTE FUNCTION keep_deployment_request_frozen();

-- Console sessions: the cookie is a random handle stored only as its SHA-256.
-- A session lives as long as the token it was opened with stays valid, so a
-- revoked token ends the session on the next request.
CREATE TABLE console_sessions (
    id_hash BYTEA PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    org_id UUID NOT NULL REFERENCES organizations(id),
    kind TEXT NOT NULL CHECK (kind IN ('a','s','u')),
    principal_id UUID NOT NULL,
    token_hash BYTEA NOT NULL REFERENCES tokens(token_hash),
    csrf TEXT NOT NULL CHECK (csrf ~ '^[a-z2-7]{52}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX console_sessions_expiry_idx ON console_sessions(expires_at);

ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided'));

-- +goose Down
DROP TABLE console_sessions;
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result')) NOT VALID;
DROP TRIGGER deployment_requests_frozen ON deployment_requests;
DROP FUNCTION keep_deployment_request_frozen();
DROP TRIGGER approval_requests_frozen ON approval_requests;
DROP FUNCTION keep_approval_frozen();
DROP INDEX approval_requests_org_status_idx;
ALTER TABLE approval_requests
    DROP COLUMN decision_reason, DROP COLUMN expires_at, DROP COLUMN requester_via,
    DROP COLUMN requester_sponsor_id, DROP COLUMN requester_id, DROP COLUMN requester_type;
