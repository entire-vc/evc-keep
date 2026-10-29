-- +goose Up
-- Replay guard of the Mesh secrets API: one row per accepted signed request.
-- A signed PUT or resolve carries a nonce inside the signed message; the
-- primary key makes a second use of the same nonce insert nothing. The
-- timestamp window is five minutes either way, so a row must outlive ten
-- minutes; the server prunes rows older than fifteen, which can never reopen
-- the window because the timestamp check refuses anything older than five.
CREATE TABLE mesh_secret_nonces (
    workspace_id UUID NOT NULL REFERENCES mesh_installations(workspace_id) ON DELETE CASCADE,
    nonce TEXT NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{16,64}$'),
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, nonce)
);
CREATE INDEX mesh_secret_nonces_seen_at ON mesh_secret_nonces (seen_at);

-- +goose Down
DROP TABLE mesh_secret_nonces;
