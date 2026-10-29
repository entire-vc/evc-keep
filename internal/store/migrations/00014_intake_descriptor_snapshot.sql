-- +goose Up
-- Nullable columns preserve compatibility with previously issued links.
-- Legacy links have no signed snapshot and are refused by descriptor v2.
ALTER TABLE intake_links
    ADD COLUMN secret_name TEXT,
    ADD COLUMN scope TEXT,
    ADD COLUMN store_name TEXT,
    ADD COLUMN class TEXT;

-- +goose Down
-- Request state, token hashes and historical journal records remain intact.
ALTER TABLE intake_links
    DROP COLUMN class,
    DROP COLUMN store_name,
    DROP COLUMN scope,
    DROP COLUMN secret_name;
