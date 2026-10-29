-- +goose Up
-- An input link a rotation issued (mode human_input) starts the layout of the
-- entered value when it completes. The mark is a table of its own: the link
-- row, and the runner and carrier tables beside it, keep their columns.
-- started_at NULL on a completed link is the durable pending layout: the value
-- is sealed, no run has laid it out yet, and the sweeper finishes the job after
-- a failed hook or a restart. claim_token/claimed_until keep two workers off one
-- row; attempts bounds the retries of a failure that does not go away.
CREATE TABLE intake_rotation_links (
    org_id UUID NOT NULL,
    request_id UUID NOT NULL REFERENCES intake_links(request_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    claimed_until TIMESTAMPTZ,
    claim_token UUID,
    attempts INT NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, request_id)
);

-- +goose Down
DROP TABLE intake_rotation_links;
