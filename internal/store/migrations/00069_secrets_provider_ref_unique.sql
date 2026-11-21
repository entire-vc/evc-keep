-- A provider_ref is unique within its store, whatever the secret's status.
-- The built-in provider keys a value by (store owner scope, provider_ref), so
-- two catalog rows with one locator in one store share one value: a ref
-- created in a member's own scope could read the other row's value through a
-- deploy and overwrite it through an input link or a rotation. A disabled
-- row keeps its locator: disabling is reversible and the value is not erased.
-- Existing duplicates stop the upgrade; they are never repaired here, and the
-- error names no locator. Find them with:
--   SELECT org_id, store_id, count(*) FROM secrets
--   GROUP BY org_id, store_id, provider_ref HAVING count(*) > 1;
-- +goose Up
LOCK TABLE secrets IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM secrets
        GROUP BY org_id, store_id, provider_ref HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'secrets share a provider_ref in one store; re-point or remove the duplicates before migrating';
    END IF;
END $$;
-- +goose StatementEnd
CREATE UNIQUE INDEX secrets_provider_ref_per_store
    ON secrets (org_id, store_id, provider_ref);

-- +goose Down
DROP INDEX secrets_provider_ref_per_store;
