-- One built-in storage namespace per owner scope, including disabled stores.
-- Existing envelopes and their authenticated data keep the same identity.
-- +goose Up
LOCK TABLE stores IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM stores WHERE provider = 'builtin'
        GROUP BY org_id, owner_scope_level, owner_scope_id HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'duplicate builtin stores at one owner scope; resolve duplicate catalog entries before migrating';
    END IF;
END $$;
-- +goose StatementEnd
CREATE UNIQUE INDEX stores_one_builtin_per_scope
    ON stores (org_id, owner_scope_level, owner_scope_id) WHERE provider = 'builtin';

-- +goose Down
DROP INDEX stores_one_builtin_per_scope;
