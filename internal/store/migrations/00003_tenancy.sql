-- +goose Up
-- Tenancy model, built on top of 00002_identity.sql: organizations, users,
-- agents, services and memberships already exist there (with their org_id
-- columns and composite (org_id, id) keys), so this migration only adds what
-- the tenant hierarchy needs beyond them and creates the two levels that
-- do not exist yet, workspaces and projects. Every table in the schema
-- carries org_id, its primary isolation filter: internal/tenancy and
-- internal/catalog never expose a repository function without an org_id
-- parameter, taken from the caller's identity.
--
-- scope_level tokens in the tables below match the wire notation used for
-- scopes everywhere else ('org', 'ws', 'proj', 'user') and are distinct
-- from organizations.key_level's vocabulary ('user' / 'project' /
-- 'workspace' / 'organization', shared with internal/builtin/sealer.Level),
-- which is a different setting entirely.

-- Key level: the granularity at which the built-in provider separates KEKs.
-- Storage only: internal/tenancy never reads it to make a cryptographic
-- decision; internal/builtin/sealer does, once it persists KEK records.
ALTER TABLE organizations
    ADD COLUMN key_level TEXT NOT NULL DEFAULT 'user'
        CHECK (key_level IN ('user', 'project', 'workspace', 'organization'));

CREATE TABLE workspaces (
    id           UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations (id),
    name         TEXT NOT NULL,
    -- Set in plugin mode: a reference to the workspace in the host system.
    external_ref TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- (org_id, id) is referenced by the composite foreign keys of the child
    -- tables, which keeps a workspace's descendants pinned to the same
    -- organization at the schema level, not just in application code.
    UNIQUE (org_id, id)
);

CREATE TABLE projects (
    id           UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations (id),
    workspace_id UUID NOT NULL,
    name         TEXT NOT NULL,
    external_ref TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, workspace_id) REFERENCES workspaces (org_id, id),
    UNIQUE (org_id, id)
);

-- A departed user's own scope and its secrets are not deleted, only marked,
-- so agents sponsored by the user can be cut off (fail closed) without
-- losing the user's own catalog.
ALTER TABLE users
    ADD COLUMN external_ref TEXT,
    ADD COLUMN status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
    ADD COLUMN removed_at   TIMESTAMPTZ,
    ADD CONSTRAINT users_removed_at_matches_status CHECK ((status = 'removed') = (removed_at IS NOT NULL));

ALTER TABLE agents
    ADD COLUMN external_ref TEXT,
    ADD COLUMN status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed'));

-- keep_validate_scope backs the CHECK constraints on the catalog tables that
-- store a polymorphic (level, id) scope reference, and the INSERTs that
-- write a scope into services.owner_scope / memberships.scope (both TEXT,
-- "level:id", owned by 00002_identity.sql). It is evaluated once, at
-- INSERT/UPDATE time of the row carrying the constraint, which is what is
-- needed here: this schema never deletes an organization, workspace,
-- project or user row (a departed user is marked removed), so there is
-- nothing for a later deletion to invalidate.
-- +goose StatementBegin
CREATE FUNCTION keep_validate_scope(p_org_id UUID, p_level TEXT, p_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    CASE p_level
        WHEN 'org' THEN
            RETURN p_id = p_org_id;
        WHEN 'ws' THEN
            RETURN EXISTS (SELECT 1 FROM workspaces WHERE id = p_id AND org_id = p_org_id);
        WHEN 'proj' THEN
            RETURN EXISTS (SELECT 1 FROM projects WHERE id = p_id AND org_id = p_org_id);
        WHEN 'user' THEN
            RETURN EXISTS (SELECT 1 FROM users WHERE id = p_id AND org_id = p_org_id);
        ELSE
            RETURN FALSE;
    END CASE;
END;
$$ LANGUAGE plpgsql STABLE;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION keep_validate_scope(UUID, TEXT, UUID);
ALTER TABLE agents
    DROP COLUMN status,
    DROP COLUMN external_ref;
ALTER TABLE users
    DROP CONSTRAINT users_removed_at_matches_status,
    DROP COLUMN removed_at,
    DROP COLUMN status,
    DROP COLUMN external_ref;
DROP TABLE projects;
DROP TABLE workspaces;
ALTER TABLE organizations DROP COLUMN key_level;
