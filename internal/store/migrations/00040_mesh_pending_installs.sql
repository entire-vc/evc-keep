-- +goose Up
-- Binding window of the Mesh install handshake. Mesh calls POST /mesh/install
-- without a bearer, signed with the workspace's signing secret; Keep binds the
-- workspace only inside a window an organisation admin opened for it. One row
-- per workspace, deleted when the binding consumes it or once it has expired.
-- secret_sha256 is the full SHA-256 of the signing secret in lowercase hex, as
-- the admin computed it: no value is stored here.
CREATE TABLE mesh_pending_installs (
    workspace_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    opened_by UUID NOT NULL,
    mesh_url TEXT NOT NULL CHECK (char_length(mesh_url) <= 512),
    secret_sha256 TEXT NOT NULL CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

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
                     'secret.rotate','mesh.secret.put','mesh.secret.resolve','org.bootstrap','mesh.install.pending'));

-- +goose Down
-- Journal rows of the window action stay (append-only, hash-chained); the
-- older CHECK is NOT VALID, so it only refuses new inserts.
DROP TABLE mesh_pending_installs;
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
                     'secret.rotate','mesh.secret.put','mesh.secret.resolve','org.bootstrap')) NOT VALID;
