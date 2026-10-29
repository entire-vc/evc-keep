-- +goose Up
-- The new REST routes that issue and revoke agent/service tokens are
-- security-relevant actions the R-AUD-1 journal
-- must be able to name (threat model §4.2's own §4.2 action registry,
-- internal/audit.registeredActions). audit_records_action_closed is a
-- second, database-level barrier behind that Go-level registry (00005's own
-- comment) and must be widened in the same change, or a valid Go Record
-- would fail to insert.
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records
    ADD CONSTRAINT audit_records_action_closed
        CHECK (action IN ('secret.create_ref', 'secret.input', 'secret.deploy', 'secret.disable',
                          'runner.enroll', 'exec.run', 'kek.purge',
                          'org.key_level.changed', 'org.key_level.change_denied',
                          'org.key_level.change_failed',
                          'identity.token_issue', 'identity.token_revoke'));

-- +goose Down
ALTER TABLE audit_records DROP CONSTRAINT audit_records_action_closed;
ALTER TABLE audit_records
    ADD CONSTRAINT audit_records_action_closed
        CHECK (action IN ('secret.create_ref', 'secret.input', 'secret.deploy', 'secret.disable',
                          'runner.enroll', 'exec.run', 'kek.purge',
                          'org.key_level.changed', 'org.key_level.change_denied',
                          'org.key_level.change_failed'));
