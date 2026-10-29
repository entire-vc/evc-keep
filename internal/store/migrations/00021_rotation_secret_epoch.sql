-- +goose Up
-- The fencing epoch belongs to the secret: a carrier keeps the highest epoch it
-- accepted for the secret, so every later run of the same secret must claim a
-- strictly higher one. One row per secret; the claim bumps it in the same
-- statement that takes the lease, under the row lock of the run and the counter.
CREATE TABLE rotation_secret_epochs (
    org_id UUID NOT NULL REFERENCES organizations(id),
    secret_id UUID NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch >= 0),
    PRIMARY KEY (org_id, secret_id)
);

-- +goose Down
DROP TABLE rotation_secret_epochs;
