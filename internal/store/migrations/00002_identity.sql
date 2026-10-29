-- Identity schema: who can authenticate to Keep (users, agents, services)
-- and what a token proves. See ADR-001 §6.
--
-- Overlaps with a future tenancy/catalog migration: organizations, users,
-- agents, services, and memberships are also needed there. Whichever MR
-- merges second rebases this migration against the other's — the two
-- definitions are not meant to coexist in the final history. This file is
-- written to be the easy side of that rebase: every CREATE TABLE below is
-- additive and none of them assumes anything about a catalog package's own
-- OverrideLock/StoreBinding/secrets tables.
--
-- id columns are UUIDv7, generated in Go (see internal/identity, and
-- internal/reqid's doc for why) — never DEFAULT gen_random_uuid(), which
-- is UUIDv4.
--
-- +goose Up
CREATE TABLE organizations (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id         UUID PRIMARY KEY,
    org_id     UUID NOT NULL REFERENCES organizations(id),
    email      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, email),
    -- Lets agents/memberships below declare a composite foreign key
    -- (org_id, user_id) → users(org_id, id), so the database itself
    -- refuses a row whose org_id doesn't match its user's actual org —
    -- not just an application-level check.
    UNIQUE (org_id, id)
);

-- An agent acts for its sponsor (the user who connected it) and never has
-- more access than the sponsor — tenancy model §4.
CREATE TABLE agents (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id),
    sponsor_user_id UUID NOT NULL,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, sponsor_user_id) REFERENCES users (org_id, id)
);

-- A service has no sponsor; it belongs to a scope directly (tenancy model §1).
CREATE TABLE services (
    id          UUID PRIMARY KEY,
    org_id      UUID NOT NULL REFERENCES organizations(id),
    owner_scope TEXT NOT NULL,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A user's role within one scope ("org:<id>", "ws:<id>", "proj:<id>",
-- "user:<id>" — tenancy model §1). The role vocabulary is this package's
-- own decision (no prior migration defines one) — see
-- internal/identity/rights.go; flagged for a future catalog package to
-- reconcile if it needs a richer model once real authorization checks land
-- there.
CREATE TABLE memberships (
    id         UUID PRIMARY KEY,
    org_id     UUID NOT NULL REFERENCES organizations(id),
    user_id    UUID NOT NULL,
    scope      TEXT NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('viewer', 'member', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, scope),
    FOREIGN KEY (org_id, user_id) REFERENCES users (org_id, id)
);

-- Grants beyond an agent's default (read_metadata, deploy) — rotate and
-- create_ref require one of these rows. No row for the defaults: they
-- apply unconditionally, see internal/identity/rights.go.
CREATE TABLE agent_grants (
    id         UUID PRIMARY KEY,
    org_id     UUID NOT NULL REFERENCES organizations(id),
    agent_id   UUID NOT NULL,
    permission TEXT NOT NULL CHECK (permission IN ('rotate', 'create_ref')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, permission),
    FOREIGN KEY (org_id, agent_id) REFERENCES agents (org_id, id)
);

-- A token's row never holds the token itself — only its SHA-256 hash, a
-- token_id, and last4 for a human to recognize which token is which. See
-- internal/identity's doc and the threat model: the plaintext is returned
-- exactly once, in the issuance response, and never stored anywhere.
--
-- principal_id is deliberately not a foreign key: which table it points
-- into (users/agents/services) depends on kind, and Postgres has no
-- conditional FK without a trigger. internal/identity validates it against
-- the right table before issuing, and again on every authentication.
CREATE TABLE tokens (
    id           UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations(id),
    kind         TEXT NOT NULL CHECK (kind IN ('a', 's', 'u')),
    principal_id UUID NOT NULL,
    token_hash   BYTEA NOT NULL,
    last4        TEXT NOT NULL,
    scope        TEXT NOT NULL,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (token_hash)
);
CREATE INDEX tokens_org_id_idx ON tokens (org_id);
CREATE INDEX tokens_principal_idx ON tokens (kind, principal_id);

-- +goose Down
DROP TABLE tokens;
DROP TABLE agent_grants;
DROP TABLE memberships;
DROP TABLE services;
DROP TABLE agents;
DROP TABLE users;
DROP TABLE organizations;
