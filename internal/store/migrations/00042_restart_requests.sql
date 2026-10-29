-- +goose Up
-- Queue of lane restart requests, filled after a service key is activated and
-- drained by a poller on the host that runs the lane: the server cannot reach
-- that host, so the hook is a pull. A row carries names, a version label and a
-- kfp1 fingerprint, never a key value. A claim leases a row for five minutes;
-- a pending row older than fifteen minutes is expired by the next claim.
CREATE TABLE restart_requests (
    request_id  UUID PRIMARY KEY,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    lane        TEXT NOT NULL CHECK (lane ~ '^[A-Za-z][A-Za-z0-9_-]{0,31}$'),
    key_version TEXT NOT NULL CHECK (key_version ~ '^[A-Za-z0-9._-]{1,64}$'),
    fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^kfp1:[a-z0-9]{1,16}:[a-z2-7]{16}$'),
    state       TEXT NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending', 'claimed', 'done', 'nothing_running', 'failed', 'expired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at  TIMESTAMPTZ,
    lease_until TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    -- claim_token fences a claim: the SHA-256 of 16 random bytes handed out at
    -- the claim, new at every claim, kept on a finished row so a repeat of the
    -- same ack is recognized. The token itself is never stored. Not a key value.
    claim_token BYTEA CHECK (claim_token IS NULL OR octet_length(claim_token) = 32),
    CHECK ((state = 'claimed') = (lease_until IS NOT NULL)),
    CHECK (state NOT IN ('claimed', 'done', 'nothing_running', 'failed') OR claim_token IS NOT NULL),
    CHECK ((state IN ('done', 'nothing_running', 'failed', 'expired')) = (finished_at IS NOT NULL))
);
CREATE INDEX restart_requests_open_idx ON restart_requests (org_id, created_at)
    WHERE state IN ('pending', 'claimed');

-- +goose Down
DROP TABLE restart_requests;
