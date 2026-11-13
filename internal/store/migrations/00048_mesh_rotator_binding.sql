-- +goose Up
-- keep-rotator is a companion identity of an existing Keep installation: same
-- organisation, workspace and Mesh address, its own signing secret and its own
-- admin window. Nothing here touches the keep installation or its window: a
-- keep window never binds the rotator, and a rotator window never binds keep.
-- secret_sha256 is the full SHA-256 of the rotator's signing secret in
-- lowercase hex, as the admin computed it; no value is stored. The secret
-- itself is sealed in the envelope store (mesh/<workspace_id>/rotator_signing_secret).
-- Both tables follow the installation: removing it removes the window and
-- the binding.
CREATE TABLE mesh_rotator_pending_installs (
    workspace_id UUID PRIMARY KEY REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id),
    opened_by UUID NOT NULL,
    secret_sha256 TEXT NOT NULL CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE mesh_rotator_bindings (
    workspace_id UUID PRIMARY KEY REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id),
    bound_by UUID NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE mesh_rotator_bindings;
DROP TABLE mesh_rotator_pending_installs;
