-- +goose Up
-- Catalog (tenancy-model doc §1, §3): where a secret's *reference* lives.
-- secrets and secret_versions hold metadata only — see catalog_schema_test.go
-- (internal/catalog) for the closed column list this migration must not grow
-- past without that test failing first. No column here can ever hold a
-- value or a ciphertext; those live in the built-in provider's own tables
-- or in an external provider entirely.

CREATE TABLE stores (
    id                 UUID PRIMARY KEY,
    org_id             UUID NOT NULL REFERENCES organizations (id),
    provider           TEXT NOT NULL,
    name               TEXT NOT NULL,
    owner_scope_level  TEXT NOT NULL CHECK (owner_scope_level IN ('org', 'ws', 'proj', 'user')),
    owner_scope_id     UUID NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (keep_validate_scope(org_id, owner_scope_level, owner_scope_id)),
    UNIQUE (org_id, id)
);

-- store_bindings: "at this scope, the default store is this one" (§1, §3).
-- One binding per scope — create-ref's upward walk (catalog.ResolveStore)
-- stops at the first one it finds.
CREATE TABLE store_bindings (
    id          UUID PRIMARY KEY,
    org_id      UUID NOT NULL REFERENCES organizations (id),
    scope_level TEXT NOT NULL CHECK (scope_level IN ('org', 'ws', 'proj', 'user')),
    scope_id    UUID NOT NULL,
    store_id    UUID NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (keep_validate_scope(org_id, scope_level, scope_id)),
    FOREIGN KEY (org_id, store_id) REFERENCES stores (org_id, id),
    UNIQUE (org_id, scope_level, scope_id)
);

-- override_locks (§3): "below this level, this selector cannot be
-- (re)defined / must live in one of these stores." Locks only narrow —
-- resolution and creation enforcement live in internal/tenancy.Resolve and
-- internal/catalog.CreateRef, not here; the schema only stores the policy.
--
-- mode='store' locks are enforced at CreateRef time (store-choice policy),
-- never by internal/tenancy.Resolve, which only ever evaluates 'name' and
-- 'class' locks (tenancy model §3 step 2). Accepted decision (scenario C5):
-- existing references are not re-resolved when a store lock appears later —
-- a secret created before the lock keeps resolving and keeps its store; the
-- lock governs where NEW secrets may be created.
CREATE TABLE override_locks (
    id                 UUID PRIMARY KEY,
    org_id             UUID NOT NULL REFERENCES organizations (id),
    -- Never 'user': nothing sits below the user level for a lock to block.
    scope_level        TEXT NOT NULL CHECK (scope_level IN ('org', 'ws', 'proj')),
    scope_id           UUID NOT NULL,
    selector_name      TEXT,
    selector_class     TEXT,
    mode               TEXT NOT NULL CHECK (mode IN ('name', 'class', 'store')),
    allowed_store_ids  UUID[],
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (keep_validate_scope(org_id, scope_level, scope_id)),
    CHECK (selector_name IS NOT NULL OR selector_class IS NOT NULL),
    -- mode='name' needs a name selector, 'class'/'store' need a class
    -- selector — store-mode restricts "secrets of this class", same as the
    -- doc's C5 (`selector=class:prod, mode=store`).
    CHECK ((mode = 'name') = (selector_name IS NOT NULL)),
    CHECK ((mode IN ('class', 'store')) = (selector_class IS NOT NULL)),
    CHECK ((mode = 'store') = (allowed_store_ids IS NOT NULL AND array_length(allowed_store_ids, 1) > 0))
);

CREATE INDEX idx_override_locks_scope ON override_locks (org_id, scope_level, scope_id);

CREATE TABLE secrets (
    id           UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations (id),
    scope_level  TEXT NOT NULL CHECK (scope_level IN ('org', 'ws', 'proj', 'user')),
    scope_id     UUID NOT NULL,
    name         TEXT NOT NULL,
    class        TEXT NOT NULL,
    type         TEXT NOT NULL,
    store_id     UUID NOT NULL,
    -- provider_ref: the provider-specific locator (pkg/provider.Ref.Path) —
    -- metadata, never a value. The locator shape itself is validated
    -- elsewhere, not by this migration.
    provider_ref TEXT NOT NULL,
    -- description: free text a human attaches to the secret ("prod DB
    -- password for the orders service"). The leak test in
    -- catalog_test.go explicitly canaries this column too, alongside name
    -- and provider_ref. Nullable: most secrets will have none.
    description  TEXT,
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (keep_validate_scope(org_id, scope_level, scope_id)),
    FOREIGN KEY (org_id, store_id) REFERENCES stores (org_id, id),
    UNIQUE (org_id, scope_level, scope_id, name),
    UNIQUE (org_id, id)
);

CREATE INDEX idx_secrets_scope ON secrets (org_id, scope_level, scope_id);

-- secret_versions: one row per pkg/provider.Meta the provider ever returned
-- for a Write. fingerprint is a keyed HMAC (pkg/fingerprint) — never a plain
-- hash of the value, and never the value itself; length is Meta.Length, a
-- byte count, not the value.
CREATE TABLE secret_versions (
    id               UUID PRIMARY KEY,
    org_id           UUID NOT NULL REFERENCES organizations (id),
    secret_id        UUID NOT NULL,
    provider_version TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    length           INTEGER NOT NULL CHECK (length >= 0),
    disabled         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, secret_id) REFERENCES secrets (org_id, id),
    UNIQUE (org_id, secret_id, provider_version)
);

CREATE INDEX idx_secret_versions_secret ON secret_versions (org_id, secret_id);

-- +goose Down
DROP TABLE secret_versions;
DROP TABLE secrets;
DROP TABLE override_locks;
DROP TABLE store_bindings;
DROP TABLE stores;
