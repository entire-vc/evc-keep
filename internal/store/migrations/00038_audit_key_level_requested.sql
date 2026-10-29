-- +goose Up
-- A key-level change is journaled before it starts: the request is written
-- first and the change runs only when that write succeeded. The closed action
-- registry gains the request action. Metadata only: no value, no key.
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
                     'secret.rotate','mesh.secret.put','mesh.secret.resolve'));

-- +goose Down
-- Journal rows of the request action stay (append-only, hash-chained) and
-- remain verifiable; the older CHECK is NOT VALID, so it only refuses new
-- inserts.
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records ADD CONSTRAINT audit_records_action_closed
    CHECK (action IN ('secret.create_ref','secret.input','secret.deploy','secret.disable',
                     'runner.enroll','runner.enroll_token_issue','runner.revoke','runner.renew',
                     'exec.run','kek.purge','org.key_level.changed','org.key_level.change_denied',
                     'org.key_level.change_failed','identity.token_issue','identity.token_revoke',
                     'intake.link_issued','intake.completed','intake.expired',
                     'deploy.requested','deploy.policy_decision','deploy.result',
                     'approval.requested','approval.decided','carrier.verify','mesh.install',
                     'secret.rotate','mesh.secret.put','mesh.secret.resolve')) NOT VALID;
