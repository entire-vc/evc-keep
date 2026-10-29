-- Storage for the built-in provider (internal/builtin): the key-encryption
-- keys of internal/builtin/sealer's hierarchy and the envelope of every
-- secret version. Nothing here is plaintext — see internal/builtin/sealer's
-- package doc for the key hierarchy and ADR-001 §5.
--
-- +goose Up

-- One row per KEK. domain_key is the stable string sealer.Scope.key() would
-- produce for the scope this KEK protects; domain_org/workspace/project/user
-- are the same scope's fields, kept so a key-level change can recompute
-- sealer.Domain(scope, level) without re-deriving it from domain_key. At
-- most one KEK is 'active' for a given (org_id, domain_key) at a time — a
-- key-level change retires the old one and a fresh KEK becomes active for
-- the new domain; a retired KEK stays readable (old DEKs still name it)
-- until Purge finds nothing references it any more and deletes it.
CREATE TABLE keep_kek (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    domain_key       TEXT NOT NULL,
    domain_org       TEXT NOT NULL,
    domain_workspace TEXT NOT NULL DEFAULT '',
    domain_project   TEXT NOT NULL DEFAULT '',
    domain_user      TEXT NOT NULL DEFAULT '',
    root_key_id      TEXT NOT NULL,
    wrapped          BYTEA NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX keep_kek_active_domain ON keep_kek (org_id, domain_key) WHERE state = 'active';
CREATE INDEX keep_kek_org ON keep_kek (org_id);

-- One row per secret version, of the built-in provider's own secrets and of
-- a store's fingerprint key (see internal/builtin's provider.go — the
-- fingerprint key is sealed the same way, under a reserved secret id).
-- wrapped_dek AND kek_id are both NULL exactly for a crypto-erased version:
-- ciphertext stays (so the row's presence and length are still visible) but
-- is permanently undecryptable, and status is 'erased'. kek_id must be
-- cleared too, not only wrapped_dek — while it still named a KEK, that KEK
-- could never be purged (Each/Purge would keep treating it as referenced),
-- so the crypto-erasure was only as final as the KEK never actually being
-- destroyed; a PostgreSQL UPDATE also leaves the pre-erase row version as a
-- recoverable dead tuple until VACUUM, so real irreversibility depends on
-- the KEK itself eventually becoming unpurgeable-by-nothing and getting
-- purged (Sealer.Purge), not merely on this row's current wrapped_dek being
-- NULL. store_workspace/project/user default to '' the same way
-- sealer.Scope's fields do, so a user-scoped store's row and a
-- workspace-scoped store's row can share the same (org, workspace, project,
-- user) index without NULL-vs-NULL surprises. store_org is this row's
-- organisation too (a Scope's Org is always its owning organisation) — a
-- separate org_id column would only ever repeat it, so org-wide queries
-- (ChangeLevel/Purge) filter on store_org directly.
CREATE TABLE keep_envelope (
    store_org        TEXT NOT NULL,
    store_workspace  TEXT NOT NULL DEFAULT '',
    store_project    TEXT NOT NULL DEFAULT '',
    store_user       TEXT NOT NULL DEFAULT '',
    secret_id        TEXT NOT NULL,
    name             TEXT NOT NULL,
    version          BIGINT NOT NULL,
    kek_id           TEXT REFERENCES keep_kek (id),
    wrapped_dek      BYTEA,
    ciphertext       BYTEA NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'erased')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (store_org, store_workspace, store_project, store_user, secret_id, version)
);

CREATE INDEX keep_envelope_org ON keep_envelope (store_org);

-- One row per organisation's key level (sealer/level.go's Level) — before
-- this table, the level lived only in the Sealer process's memory, which a
-- restart silently reset to DefaultLevel with no audit trail, and which two
-- server processes could each believe independently, racing to create an
-- active KEK under their own view of it. No row for an org means
-- DefaultLevel, the same "absent means default" semantics the in-memory map
-- had.
CREATE TABLE keep_org_key_level (
    org_id     TEXT PRIMARY KEY,
    level      TEXT NOT NULL CHECK (level IN ('user', 'project', 'workspace', 'organization')),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE keep_org_key_level;
DROP TABLE keep_envelope;
DROP TABLE keep_kek;
