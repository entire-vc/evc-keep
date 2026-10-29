-- +goose Up
-- R-AUD-1 audit journal (threat model §4.2). Two tables:
--
--   audit_chain_heads — one row per organization, holding that org's
--   current chain position and last hash. internal/audit.Journal.Append
--   locks this row (an INSERT ... ON CONFLICT upsert, which locks even on a first insert) to serialize concurrent
--   appends within one organization (see internal/audit/doc.go); two
--   organizations append fully in parallel since they lock different rows.
--
--   audit_records — the append-only journal itself, one row per R-AUD-1
--   record, every column a metadata field from the threat model's closed
--   §4.2 schema. There is no column here that could hold a secret's value
--   or ciphertext — see internal/audit/record_test.go's schema-closedness
--   test for the Go-level guarantee this table mirrors.
--
-- "keep_app" is a role distinct from whatever role owns this migration
-- (the role connecting via KEEP_DATABASE_URL, "keep" in CI/local dev): it
-- is granted only SELECT+INSERT on audit_records, never UPDATE or DELETE —
-- the threat model's "writes are INSERT-only" requirement enforced at the
-- database layer, not just in application code. internal/audit.Journal
-- executes every append inside a transaction that does `SET LOCAL ROLE
-- keep_app` immediately after BEGIN, so even a superuser connection (as
-- "keep" is, in the docker postgres image CI and local dev both use)
-- genuinely loses UPDATE/DELETE on this one table for that transaction —
-- verified empirically before writing this migration: SET LOCAL ROLE
-- correctly drops a superuser login's bypass for the rest of that
-- transaction, checked against the role's own actual grants. See
-- internal/audit/rights_test.go.
--
-- keep_app has no privileges on audit_chain_heads beyond what it needs
-- (SELECT/INSERT/UPDATE) — that table is Journal-internal bookkeeping, not
-- part of the append-only guarantee the threat model states specifically
-- for audit_records.
--
-- CREATE ROLE has no IF NOT EXISTS form in PostgreSQL, and roles are
-- cluster-wide (not dropped by a per-database schema reset), so this is
-- guarded explicitly — re-running this migration's Up against a database
-- whose cluster already has the role (a repeated local `migrate up` after
-- a schema-only reset) must not fail.
-- +goose StatementBegin
-- goose splits a migration file into individual statements on ';' unless
-- told otherwise — it does not understand PL/pgSQL's dollar-quoting, so
-- without these markers it would cut this DO block apart at the first
-- semicolon inside it. Confirmed locally: omitting them fails migrate up
-- with "unterminated dollar-quoted string".
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keep_app') THEN
        CREATE ROLE keep_app NOLOGIN;
    END IF;
END
$$;
-- +goose StatementEnd

-- The role connecting as this migration runs must be able to SET ROLE
-- keep_app later (Journal does this every append) without needing to be a
-- cluster superuser — GRANT ... TO makes that work for any role, superuser
-- or not.
GRANT keep_app TO CURRENT_USER;

-- USAGE on the schema itself, not just privileges on the tables inside it —
-- explicit rather than relying on the original "public" schema's default
-- GRANT ... TO PUBLIC. A role with a table privilege but no schema USAGE
-- gets exactly the same "relation ... does not exist" error a role with no
-- privilege at all gets (Postgres does not reveal an object's existence to
-- a role that cannot reach its schema) — caught in development against a
-- test database whose "public" schema had been dropped and recreated
-- (internal/audit/testhelpers_test.go, for a schema-reset between test
-- runs), which does NOT carry that default PUBLIC grant the way the
-- original initdb-created "public" schema does. A pristine database (every
-- real deployment, and CI's own fresh postgres service) would have worked
-- without this line — it is here so keep_app's access does not depend on
-- which kind of "public" schema it happens to run against.
GRANT USAGE ON SCHEMA public TO keep_app;

CREATE TABLE audit_chain_heads (
    org_id   TEXT PRIMARY KEY,
    position BIGINT NOT NULL DEFAULT 0,
    hash     TEXT   NOT NULL
);

CREATE TABLE audit_records (
    id                   TEXT        PRIMARY KEY,
    org_id               TEXT        NOT NULL,
    org_seq              BIGINT      NOT NULL,
    ts                   TIMESTAMPTZ NOT NULL,
    request_id           TEXT        NOT NULL,
    scope                TEXT        NOT NULL,
    actor_type           TEXT        NOT NULL,
    actor_id             TEXT        NOT NULL,
    actor_sponsor_id     TEXT        NOT NULL DEFAULT '',
    actor_via            TEXT        NOT NULL,
    intent_task_ref      TEXT        NOT NULL DEFAULT '',
    intent_session_ref   TEXT        NOT NULL DEFAULT '',
    intent_reason        TEXT        NOT NULL DEFAULT '',
    action               TEXT        NOT NULL,
    secret_id            TEXT        NOT NULL DEFAULT '',
    secret_name          TEXT        NOT NULL DEFAULT '',
    secret_version       TEXT        NOT NULL DEFAULT '',
    target_runner_id     TEXT        NOT NULL DEFAULT '',
    target_host          TEXT        NOT NULL DEFAULT '',
    target_kind          TEXT        NOT NULL DEFAULT '',
    target_path          TEXT        NOT NULL DEFAULT '',
    policy_decision      TEXT        NOT NULL DEFAULT '',
    policy_rule_id       TEXT        NOT NULL DEFAULT '',
    approval_id          TEXT        NOT NULL DEFAULT '',
    approval_approver_id TEXT        NOT NULL DEFAULT '',
    approval_decided_at  TIMESTAMPTZ,
    result_status        TEXT        NOT NULL,
    result_fingerprint    TEXT        NOT NULL DEFAULT '',
    result_length         INTEGER     NOT NULL DEFAULT 0,
    result_health         TEXT        NOT NULL DEFAULT '',
    result_error_class    TEXT        NOT NULL DEFAULT '',
    prev_hash             TEXT        NOT NULL,
    hash                  TEXT        NOT NULL,
    UNIQUE (org_id, org_seq)
);

-- Second barrier behind internal/audit.Record.validate: the enumerated
-- columns take only their closed sets (the action column included: it is the
-- one field the service log line carries) and the fingerprint column only its
-- fixed shape, so free text (a backend's error message, a value
-- in an "error_class") cannot enter an append-only table even from a writer
-- that bypasses the Go types. Keep the sets in step with record.go.
ALTER TABLE audit_records
    ADD CONSTRAINT audit_records_actor_type_closed
        CHECK (actor_type IN ('agent', 'user', 'service', 'runner', 'system')),
    ADD CONSTRAINT audit_records_actor_via_closed
        CHECK (actor_via IN ('', 'api', 'cli', 'mcp', 'mesh-plugin', 'console')),
    ADD CONSTRAINT audit_records_policy_decision_closed
        CHECK (policy_decision IN ('', 'allow', 'deny', 'approval_required')),
    ADD CONSTRAINT audit_records_result_status_closed
        CHECK (result_status IN ('ok', 'failed', 'pending')),
    ADD CONSTRAINT audit_records_result_health_closed
        CHECK (result_health IN ('', 'ok', 'failed', 'skipped')),
    ADD CONSTRAINT audit_records_result_error_class_closed
        CHECK (result_error_class IN ('', 'invalid_argument', 'not_found', 'permission_denied',
                                      'policy_denied', 'provider_error', 'target_error', 'internal')),
    ADD CONSTRAINT audit_records_result_fingerprint_shape
        CHECK (result_fingerprint = '' OR result_fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    ADD CONSTRAINT audit_records_action_closed
        CHECK (action IN ('secret.create_ref', 'secret.input', 'secret.deploy', 'secret.disable',
                          'runner.enroll', 'exec.run', 'kek.purge',
                          'org.key_level.changed', 'org.key_level.change_denied',
                          'org.key_level.change_failed')),
    ADD CONSTRAINT audit_records_result_length_nonneg
        CHECK (result_length >= 0),
    ADD CONSTRAINT audit_records_id_shape
        CHECK (id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    ADD CONSTRAINT audit_records_request_id_shape
        CHECK (request_id = '' OR request_id ~ '^[A-Za-z0-9-]{1,36}$'),
    ADD CONSTRAINT audit_records_intent_reason_bound
        CHECK (char_length(intent_reason) <= 200);

-- Verify (internal/audit/verify.go) reads one organization's records in
-- chain order; this index makes that an index-only range scan rather than
-- a sort over the whole table.
CREATE INDEX audit_records_org_seq_idx ON audit_records (org_id, org_seq);

GRANT SELECT, INSERT, UPDATE ON audit_chain_heads TO keep_app;
GRANT SELECT, INSERT ON audit_records TO keep_app;
-- No UPDATE, no DELETE on audit_records for keep_app — see the comment
-- above. Deliberately no explicit REVOKE: a role's default privilege set on
-- a newly created table is already empty until granted, so this is the
-- absence of a grant, not a narrowing of one.

-- +goose Down
DROP INDEX IF EXISTS audit_records_org_seq_idx;
DROP TABLE IF EXISTS audit_records;
DROP TABLE IF EXISTS audit_chain_heads;
-- REVOKE before DROP ROLE: a role that still holds a grant on some object
-- cannot be dropped ("role ... cannot be dropped because some objects
-- depend on it"). The two tables are already gone at this point, but
-- CURRENT_USER's membership grant (GRANT keep_app TO CURRENT_USER, above)
-- is a dependency in its own right, and so is the USAGE grant on the schema
-- (Up grants it; a role that still holds it cannot be dropped either).
REVOKE USAGE ON SCHEMA public FROM keep_app;
REVOKE keep_app FROM CURRENT_USER;
DROP ROLE IF EXISTS keep_app;
