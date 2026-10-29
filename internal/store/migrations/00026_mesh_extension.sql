-- +goose Up
-- Keep as a Mesh extension (Doc 06 section 2). Metadata only: the Mesh actor
-- token and both HMAC secrets live sealed in keep_envelope under the
-- mesh/<workspace_id>/... paths of the organisation's own store; nothing here
-- is a value. A Mesh workspace belongs to exactly one Keep organisation.
CREATE TABLE mesh_installations (
    workspace_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    mesh_url TEXT NOT NULL CHECK (char_length(mesh_url) <= 512),
    installed_by UUID NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per accepted event; the primary key is the replay guard: a second
-- delivery of the same event id inserts nothing and so has no effect. Rows must
-- be kept at least as long as the five-minute timestamp window; never prune
-- below that.
CREATE TABLE mesh_events (
    workspace_id UUID NOT NULL REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL CHECK (event_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    event_type TEXT NOT NULL CHECK (event_type IN ('workspace.member.added','workspace.member.removed',
        'project.created','project.updated','agent.key.issued','agent.key.revoked','task.gate.decided')),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, event_id)
);

ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided','carrier.verify','mesh.install'));

-- +goose Down
DROP TABLE mesh_events;
DROP TABLE mesh_installations;
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided','carrier.verify')) NOT VALID;
