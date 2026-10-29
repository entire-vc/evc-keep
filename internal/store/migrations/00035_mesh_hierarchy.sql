-- +goose Up
-- The Mesh hierarchy as Keep knows it (tenancy model section 2): members,
-- projects, agents and agent keys of a connected Mesh workspace, kept from
-- events and a periodic full reconciliation. Metadata only. Nothing here is a
-- value, and no agent key material (not even the public prefix) is stored: a
-- key is known by its id and label. Rows are never deleted by a sync; an
-- entity that vanished from Mesh is marked 'orphaned' so the secrets and the
-- access that hang off it survive a missed or mistaken event. state_at is the
-- moment of the Mesh fact the row reflects: an event or snapshot older than
-- it is ignored, which makes reordered and repeated deliveries harmless.
CREATE TABLE mesh_members (
    workspace_id UUID NOT NULL REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role TEXT NOT NULL CHECK (char_length(role) BETWEEN 1 AND 64),
    role_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    status TEXT NOT NULL CHECK (status IN ('active','removed','orphaned')),
    state_at TIMESTAMPTZ NOT NULL,
    orphaned_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE mesh_projects (
    workspace_id UUID NOT NULL REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    project_id UUID NOT NULL,
    slug TEXT NOT NULL DEFAULT '' CHECK (char_length(slug) <= 128),
    name TEXT NOT NULL DEFAULT '' CHECK (char_length(name) <= 256),
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    -- when each field was last stated by Mesh: a partial event moves only the
    -- fields it carries, so each field orders on its own clock
    slug_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    name_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    archived_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    status TEXT NOT NULL CHECK (status IN ('active','orphaned')),
    state_at TIMESTAMPTZ NOT NULL,
    orphaned_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, project_id)
);

CREATE TABLE mesh_agents (
    workspace_id UUID NOT NULL REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL,
    slug TEXT NOT NULL DEFAULT '' CHECK (char_length(slug) <= 128),
    slug_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    sponsor_user_id UUID,
    sponsor_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    status TEXT NOT NULL CHECK (status IN ('active','orphaned')),
    state_at TIMESTAMPTZ NOT NULL,
    orphaned_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, agent_id)
);

CREATE TABLE mesh_agent_keys (
    workspace_id UUID NOT NULL REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL,
    key_id TEXT NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    label TEXT NOT NULL DEFAULT '' CHECK (char_length(label) <= 128),
    label_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    status TEXT NOT NULL CHECK (status IN ('active','revoked','orphaned')),
    state_at TIMESTAMPTZ NOT NULL,
    orphaned_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, agent_id, key_id)
);

-- One row per workspace: the cursor (ETag) of the last full snapshot, and how
-- the last reconciliation ended. An event the sync cannot apply by itself bumps
-- dirty_seq; a reconciliation that saw it records it in synced_seq. While
-- dirty_seq > synced_seq the next fetch ignores the cursor, and a bump that
-- lands during a fetch is not lost.
CREATE TABLE mesh_sync_state (
    workspace_id UUID PRIMARY KEY REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    cursor TEXT NOT NULL DEFAULT '' CHECK (char_length(cursor) <= 128),
    dirty_seq BIGINT NOT NULL DEFAULT 0,
    synced_seq BIGINT NOT NULL DEFAULT 0,
    last_sync_at TIMESTAMPTZ,
    last_result TEXT NOT NULL DEFAULT '' CHECK (last_result IN ('','ok','not_modified','failed')),
    last_error_class TEXT NOT NULL DEFAULT '' CHECK (char_length(last_error_class) <= 64),
    orphaned_count INTEGER NOT NULL DEFAULT 0
);

-- +goose Down
DROP TABLE mesh_sync_state;
DROP TABLE mesh_agent_keys;
DROP TABLE mesh_agents;
DROP TABLE mesh_projects;
DROP TABLE mesh_members;
