-- +goose Up
-- A DualKey run that fails while laying out or verifying puts its carriers back
-- on the old version before it ends the key it issued. rolling_back is the
-- stored state in between, so a run that dies there is resumed into the same
-- rollback; it keeps the error class of the failure.
ALTER TABLE rotation_runs DROP CONSTRAINT rotation_runs_state_check;
ALTER TABLE rotation_runs ADD CONSTRAINT rotation_runs_state_check
    CHECK (state IN ('new_version','deploying','verifying','revoking_old','rolling_back','done','failed'));
-- A version a human entered has no key behind it: nothing for the rollback to end.
ALTER TABLE rotation_keys ADD COLUMN adopted BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
-- A run caught mid-rollback is closed as failed; its incident is the record.
UPDATE rotation_runs SET state='failed' WHERE state='rolling_back';
ALTER TABLE rotation_keys DROP COLUMN adopted;
ALTER TABLE rotation_runs DROP CONSTRAINT rotation_runs_state_check;
ALTER TABLE rotation_runs ADD CONSTRAINT rotation_runs_state_check
    CHECK (state IN ('new_version','deploying','verifying','revoking_old','done','failed'));
