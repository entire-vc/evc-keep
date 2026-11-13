-- +goose Up
-- Consumption history of offline scoped transfers on THIS database. A row is
-- written in the same transaction as the imported rows and the audit append,
-- so a committed import always leaves exactly one row and a rolled-back one
-- leaves none. It is node-local: it is never copied to another database by a
-- transfer, so an imported organization can be transferred again.
--
-- Only public identities and digests are stored, never a key, root id, value
-- or DSN. recipient_fingerprint is UNIQUE across all organizations: one
-- recipient keypair can be consumed once. organizations is referenced without
-- a cascading action, so deleting an organization cannot delete its ledger.
-- UPDATE, DELETE and TRUNCATE (also when reached through a cascade) are
-- refused by triggers for every role, which protects against ordinary or
-- concurrent re-import; it is not a defence against a database owner who
-- drops the triggers.
CREATE TABLE scoped_transfer_ledger (
    transfer_id           UUID PRIMARY KEY,
    recipient_fingerprint TEXT NOT NULL UNIQUE CHECK (recipient_fingerprint ~ '^[0-9a-f]{64}$'),
    org_id                UUID NOT NULL REFERENCES organizations(id),
    source_id             UUID NOT NULL,
    snapshot_id           UUID NOT NULL,
    ciphertext_checksum   TEXT NOT NULL CHECK (ciphertext_checksum ~ '^[0-9a-f]{64}$'),
    audit_head            TEXT NOT NULL CHECK (audit_head ~ '^[0-9a-f]{64}$'),
    imported_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose StatementBegin
CREATE FUNCTION scoped_transfer_ledger_refuse() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'scoped_transfer_ledger is append-only' USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER scoped_transfer_ledger_no_update_delete
    BEFORE UPDATE OR DELETE ON scoped_transfer_ledger
    FOR EACH ROW EXECUTE FUNCTION scoped_transfer_ledger_refuse();

CREATE TRIGGER scoped_transfer_ledger_no_truncate
    BEFORE TRUNCATE ON scoped_transfer_ledger
    FOR EACH STATEMENT EXECUTE FUNCTION scoped_transfer_ledger_refuse();

-- +goose Down
DROP TRIGGER scoped_transfer_ledger_no_truncate ON scoped_transfer_ledger;
DROP TRIGGER scoped_transfer_ledger_no_update_delete ON scoped_transfer_ledger;
DROP TABLE scoped_transfer_ledger;
DROP FUNCTION scoped_transfer_ledger_refuse();
