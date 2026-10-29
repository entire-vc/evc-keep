-- +goose Up
-- Confirmations through Mesh gate cards (Doc 06 section 4). Metadata only:
-- the card id, the request hash and who decided; no value, no card text.
--
-- A Mesh user may decide only if an organization admin linked them to a Keep
-- user: approval_requests.decided_by is a Keep user, so an unlinked Mesh user
-- has nobody to be recorded as.
CREATE TABLE mesh_user_links (
    workspace_id UUID NOT NULL REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    mesh_user_id UUID NOT NULL,
    org_id UUID NOT NULL,
    user_id UUID NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, mesh_user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES users(org_id, id)
);

CREATE TABLE mesh_gate_requests (
    workspace_id UUID NOT NULL REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    task_id UUID NOT NULL,
    org_id UUID NOT NULL,
    approval_id UUID NOT NULL,
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    -- Mesh identity of whoever asked, when the caller knows it; the decider
    -- may never be this id.
    initiator_ref TEXT NOT NULL DEFAULT '' CHECK (char_length(initiator_ref) <= 64),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','expired')),
    expires_at TIMESTAMPTZ NOT NULL,
    card_cancelled BOOLEAN NOT NULL DEFAULT false,
    decided_by_mesh UUID,
    decided_event TEXT CHECK (decided_event IS NULL OR char_length(decided_event) <= 128),
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, task_id),
    UNIQUE (org_id, approval_id),
    FOREIGN KEY (org_id, approval_id) REFERENCES approval_requests(org_id, id),
    CHECK ((status IN ('approved','rejected')) = (decided_at IS NOT NULL))
);
CREATE INDEX mesh_gate_requests_open_idx ON mesh_gate_requests(expires_at)
    WHERE status = 'pending' OR (status = 'expired' AND NOT card_cancelled);

-- +goose Down
DROP TABLE mesh_gate_requests;
DROP TABLE mesh_user_links;
