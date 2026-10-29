-- +goose Up
-- A federated person (external_ref "mesh:<instance_url>:<user_id>") maps to
-- exactly one user per organisation; the index is what makes find-or-create
-- race-free.
CREATE UNIQUE INDEX users_org_external_ref_key ON users (org_id, external_ref) WHERE external_ref IS NOT NULL;

-- +goose Down
DROP INDEX users_org_external_ref_key;
