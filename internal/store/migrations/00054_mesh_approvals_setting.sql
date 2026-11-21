-- +goose Up
-- The workspace setting approvals_via_mesh of the Keep extension, as Mesh last
-- sent it in the install handshake (settings snapshot). NULL: Mesh has not
-- sent it (an older Mesh, or the key is unset), and the manifest default,
-- true, applies. false: an approval of this organisation gets no Mesh card and
-- is decided in Keep's own console.
ALTER TABLE mesh_installations ADD COLUMN approvals_via_mesh BOOLEAN;

-- +goose Down
ALTER TABLE mesh_installations DROP COLUMN approvals_via_mesh;
