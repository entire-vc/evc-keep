-- +goose Up
-- A run whose worker panicked ends as failed with a fixed class.
ALTER TABLE rotation_runs DROP CONSTRAINT rotation_runs_error_class_check;
ALTER TABLE rotation_runs ADD CONSTRAINT rotation_runs_error_class_check
    CHECK (error_class IN ('','no_carriers','deploy_failed','fingerprint_mismatch','unhealthy','verify_failed','revoke_failed','prepare_failed','internal_error'));

-- +goose Down
UPDATE rotation_runs SET error_class='prepare_failed' WHERE error_class='internal_error';
ALTER TABLE rotation_runs DROP CONSTRAINT rotation_runs_error_class_check;
ALTER TABLE rotation_runs ADD CONSTRAINT rotation_runs_error_class_check
    CHECK (error_class IN ('','no_carriers','deploy_failed','fingerprint_mismatch','unhealthy','verify_failed','revoke_failed','prepare_failed'));
