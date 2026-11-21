-- +goose Up
-- Adoption shares the job transport and bound human approvals, while keeping
-- an explicit read-only request purpose. It never counts as a deployment.
ALTER TABLE deployment_requests ADD COLUMN adoption BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE deployment_requests ADD CONSTRAINT deployment_requests_adoption_target
    CHECK (NOT adoption OR (exec IS NULL AND COALESCE(target->>'Kind' = 'yaml-scalar',false)));
ALTER TABLE deployment_jobs DROP CONSTRAINT deployment_jobs_action_check;
ALTER TABLE deployment_jobs ADD CONSTRAINT deployment_jobs_action_check
    CHECK (action IN ('deploy','exec','verify','adopt'));
ALTER TABLE agent_grants DROP CONSTRAINT agent_grants_permission_check;
ALTER TABLE agent_grants ADD CONSTRAINT agent_grants_permission_check
    CHECK (permission IN ('rotate','create_ref','adopt_carrier'));

-- The immutable job retains its nonce, canonical destination and lifetime.
-- This receipt binds the accepted observation to the exact catalog version
-- and enrolled host; neither a verify nor a deployment can manufacture one.
CREATE TABLE carrier_adoption_receipts (
    org_id UUID NOT NULL,
    job_id UUID NOT NULL,
    secret_id UUID NOT NULL,
    version_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    host TEXT NOT NULL,
    target_path TEXT NOT NULL,
    target_field TEXT NOT NULL,
    version TEXT NOT NULL,
    fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id,job_id),
    FOREIGN KEY (org_id,job_id) REFERENCES deployment_jobs(org_id,id),
    FOREIGN KEY (org_id,runner_id) REFERENCES runners(org_id,id),
    FOREIGN KEY (org_id,secret_id,version_id) REFERENCES secret_versions(org_id,secret_id,id),
    FOREIGN KEY (org_id,secret_id,version) REFERENCES secret_versions(org_id,secret_id,provider_version)
);
-- +goose StatementBegin
CREATE FUNCTION keep_adoption_receipt_frozen() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'adoption receipt is immutable';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER carrier_adoption_receipts_frozen BEFORE UPDATE OR DELETE ON carrier_adoption_receipts
    FOR EACH ROW EXECUTE FUNCTION keep_adoption_receipt_frozen();
ALTER TABLE carriers ADD COLUMN provenance TEXT NOT NULL DEFAULT 'deployment'
    CHECK (provenance IN ('deployment','adoption'));
ALTER TABLE carriers ADD COLUMN adoption_runner_id UUID;
ALTER TABLE carriers ADD COLUMN attestation_job_id UUID;
ALTER TABLE carriers ADD FOREIGN KEY (org_id,adoption_runner_id) REFERENCES runners(org_id,id);
ALTER TABLE carriers ADD FOREIGN KEY (org_id,attestation_job_id) REFERENCES carrier_adoption_receipts(org_id,job_id);
ALTER TABLE carriers ADD CONSTRAINT carriers_adoption_provenance CHECK (
    (provenance='adoption' AND adoption_runner_id IS NOT NULL AND attestation_job_id IS NOT NULL AND target_kind='yaml-scalar')
    OR (provenance='deployment' AND adoption_runner_id IS NULL AND attestation_job_id IS NULL));

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
                     'carrier.adopt.requested','carrier.adopt.policy_decision','carrier.adopt.result'));


-- +goose Down
-- Refuse a schema rollback that would discard adoption authorization or
-- turn its queued reads into deployments. Roll back binaries independently.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM deployment_requests WHERE adoption)
       OR EXISTS (SELECT 1 FROM deployment_jobs WHERE action='adopt')
       OR EXISTS (SELECT 1 FROM carrier_adoption_receipts)
       OR EXISTS (SELECT 1 FROM deployment_policies WHERE COALESCE(rules->'adoption_rules','[]'::jsonb) NOT IN ('[]'::jsonb,'null'::jsonb))
       OR EXISTS (SELECT 1 FROM agent_grants WHERE permission='adopt_carrier') THEN
        RAISE EXCEPTION 'adoption metadata must be retained';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE carriers DROP CONSTRAINT carriers_adoption_provenance;
ALTER TABLE carriers DROP COLUMN attestation_job_id, DROP COLUMN adoption_runner_id, DROP COLUMN provenance;
DROP TABLE carrier_adoption_receipts;
DROP FUNCTION keep_adoption_receipt_frozen();
ALTER TABLE agent_grants DROP CONSTRAINT agent_grants_permission_check;
ALTER TABLE agent_grants ADD CONSTRAINT agent_grants_permission_check
    CHECK (permission IN ('rotate','create_ref'));
ALTER TABLE deployment_jobs DROP CONSTRAINT deployment_jobs_action_check;
ALTER TABLE deployment_jobs ADD CONSTRAINT deployment_jobs_action_check
    CHECK (action IN ('deploy','exec','verify'));
ALTER TABLE deployment_requests DROP CONSTRAINT deployment_requests_adoption_target;
ALTER TABLE deployment_requests DROP COLUMN adoption;
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
                     'store.bind_default','deploy.policy_set','mesh.token','mesh.uninstall','mesh.secret.metadata','transfer.imported','carrier.discover')) NOT VALID;
