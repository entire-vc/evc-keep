-- Bind a delivery public key and administrator-asserted host attributes to
-- enrollment. NULL columns preserve legacy registration while making its
-- delivery trust explicitly unavailable or unknown.

-- +goose Up
ALTER TABLE enroll_tokens
    ADD COLUMN host_attrs JSONB,
    ADD CONSTRAINT enroll_tokens_host_attrs_object
        CHECK (host_attrs IS NULL OR jsonb_typeof(host_attrs) = 'object');

ALTER TABLE runners
    ADD COLUMN hpke_public_key BYTEA,
    ADD COLUMN uid_shared BOOLEAN,
    ADD COLUMN host_labels JSONB,
    ADD COLUMN attrs_source TEXT,
    ADD CONSTRAINT runners_hpke_public_key_len
        CHECK (hpke_public_key IS NULL OR octet_length(hpke_public_key) = 32),
    ADD CONSTRAINT runners_host_attrs_provenance
        CHECK ((attrs_source IS NULL AND uid_shared IS NULL AND host_labels IS NULL)
            OR (attrs_source IS NOT NULL AND attrs_source = 'enroll_token' AND uid_shared IS NOT NULL
                AND host_labels IS NOT NULL AND jsonb_typeof(host_labels) = 'object'));

-- +goose Down
ALTER TABLE runners
    DROP CONSTRAINT runners_host_attrs_provenance,
    DROP CONSTRAINT runners_hpke_public_key_len,
    DROP COLUMN attrs_source,
    DROP COLUMN host_labels,
    DROP COLUMN uid_shared,
    DROP COLUMN hpke_public_key;

ALTER TABLE enroll_tokens
    DROP CONSTRAINT enroll_tokens_host_attrs_object,
    DROP COLUMN host_attrs;
