-- +goose Up
-- Resume of an active run nothing is driving: how many times it was taken, and
-- the earliest moment it may be taken again. Counters only, no value.
ALTER TABLE rotation_runs
    ADD COLUMN resume_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN resume_after TIMESTAMPTZ;

-- +goose Down
ALTER TABLE rotation_runs DROP COLUMN resume_after, DROP COLUMN resume_attempts;
