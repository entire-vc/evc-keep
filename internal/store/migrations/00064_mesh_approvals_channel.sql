-- +goose Up
-- Threat model §4.2.3. A change of the workspace setting approvals_via_mesh is
-- journaled as mesh.approvals_channel, in the transaction that changes it.
-- settings_signed_at is the X-Mesh-Timestamp (Unix seconds) of the last
-- applied settings snapshot of the workspace: a snapshot signed earlier is not
-- applied, so a delayed handshake or a replay of a signed body inside the
-- signature window cannot put back an older value. NULL: no snapshot applied.
ALTER TABLE mesh_installations ADD COLUMN settings_signed_at BIGINT;

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
                     'store.bind_default','deploy.policy_set','mesh.token','mesh.uninstall','mesh.secret.metadata','transfer.imported','carrier.discover',
                     'carrier.adopt.requested','carrier.adopt.policy_decision','carrier.adopt.result','mesh.approvals_channel'));

-- +goose Down
-- Records of the dropped action stay in the append-only journal: the restored
-- list is NOT VALID, so it binds new rows only.
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
                     'store.bind_default','deploy.policy_set','mesh.token','mesh.uninstall','mesh.secret.metadata','transfer.imported','carrier.discover',
                     'carrier.adopt.requested','carrier.adopt.policy_decision','carrier.adopt.result')) NOT VALID;
ALTER TABLE mesh_installations DROP COLUMN settings_signed_at;
