-- +goose Up
-- Runner revocation is an administrative security action. Widen the
-- append-only journal's closed registry before handlers write this action.
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records
    ADD CONSTRAINT audit_records_action_closed
        CHECK (action IN ('secret.create_ref', 'secret.input', 'secret.deploy', 'secret.disable',
                          'runner.enroll', 'runner.enroll_token_issue', 'runner.revoke', 'exec.run', 'kek.purge',
                          'org.key_level.changed', 'org.key_level.change_denied',
                          'org.key_level.change_failed',
                          'identity.token_issue', 'identity.token_revoke',
                          'intake.link_issued', 'intake.completed', 'intake.expired'));

-- +goose Down
-- Preserve historical revoke records on downgrade. NOT VALID exempts only
-- existing rows; new inserts must satisfy the previous action registry.
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records
    ADD CONSTRAINT audit_records_action_closed
        CHECK (action IN ('secret.create_ref', 'secret.input', 'secret.deploy', 'secret.disable',
                          'runner.enroll', 'exec.run', 'kek.purge',
                          'org.key_level.changed', 'org.key_level.change_denied',
                          'org.key_level.change_failed',
                          'identity.token_issue', 'identity.token_revoke',
                          'intake.link_issued', 'intake.completed', 'intake.expired')) NOT VALID;
