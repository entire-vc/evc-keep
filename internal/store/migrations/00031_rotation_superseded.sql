-- +goose Up
-- A run whose version a human superseded (a newer version was sealed while it
-- laid its own out) ends failed with the class superseded: it activated nothing.
ALTER TABLE rotation_runs DROP CONSTRAINT rotation_runs_error_class_check;
ALTER TABLE rotation_runs ADD CONSTRAINT rotation_runs_error_class_check
    CHECK (error_class IN ('','no_carriers','deploy_failed','fingerprint_mismatch','unhealthy','verify_failed','revoke_failed','prepare_failed','internal_error','superseded'));

-- +goose Down
UPDATE rotation_runs SET error_class='verify_failed' WHERE error_class='superseded';
ALTER TABLE rotation_runs DROP CONSTRAINT rotation_runs_error_class_check;
ALTER TABLE rotation_runs ADD CONSTRAINT rotation_runs_error_class_check
    CHECK (error_class IN ('','no_carriers','deploy_failed','fingerprint_mismatch','unhealthy','verify_failed','revoke_failed','prepare_failed','internal_error'));
