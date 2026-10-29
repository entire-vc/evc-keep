-- +goose Up
CREATE TABLE intake_links (
    request_id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    secret_id UUID NOT NULL,
    store_id UUID NOT NULL,
    provider_ref TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user','agent','service')),
    actor_id TEXT NOT NULL,
    sponsor_id TEXT NOT NULL DEFAULT '',
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    signing_key BYTEA NOT NULL CHECK (octet_length(signing_key) = 32),
    signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','completed','expired')),
    version TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (org_id,secret_id) REFERENCES secrets(org_id,id),
    FOREIGN KEY (org_id,store_id) REFERENCES stores(org_id,id)
);
CREATE INDEX intake_links_expiry ON intake_links(expires_at) WHERE state = 'active';
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','exec.run','kek.purge',
                     'org.key_level.changed','org.key_level.change_denied','org.key_level.change_failed',
                     'identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired'));

-- +goose Down
-- Historical journal entries must be retained. If there are intake events,
-- roll back the application while retaining this additive schema migration.
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','exec.run','kek.purge',
                     'org.key_level.changed','org.key_level.change_denied','org.key_level.change_failed',
                     'identity.token_issue','identity.token_revoke'));
DROP TABLE intake_links;
