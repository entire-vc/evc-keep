-- +goose Up
-- Two facts the rotation wiring used to guess from timestamps, kept as state.
--
-- seal_seq is the order versions of a secret were sealed in: one monotonic
-- number from a sequence, taken when the row is inserted. provider_version is a
-- text the provider chooses and created_at can tie or differ between hosts, so
-- neither orders sealed inputs; newest = the highest seal_seq.
--
-- secrets.deployed_version points at the version that is actually laid out
-- (every carrier of the secret confirmed it): the predecessor a rotation
-- revokes. NULL until a run has deployed one.
ALTER TABLE secret_versions ADD COLUMN seal_seq BIGINT;
-- Deterministic backfill: existing rows are numbered in (created_at, id) order.
UPDATE secret_versions v SET seal_seq = o.n
  FROM (SELECT id, row_number() OVER (ORDER BY created_at, id) AS n FROM secret_versions) o
 WHERE v.id = o.id;
CREATE SEQUENCE secret_versions_seal_seq_seq OWNED BY secret_versions.seal_seq;
SELECT setval('secret_versions_seal_seq_seq', COALESCE((SELECT max(seal_seq) FROM secret_versions), 0) + 1, false);
ALTER TABLE secret_versions ALTER COLUMN seal_seq SET DEFAULT nextval('secret_versions_seal_seq_seq');
ALTER TABLE secret_versions ALTER COLUMN seal_seq SET NOT NULL;
ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_seal_seq_unique UNIQUE (seal_seq);

ALTER TABLE secrets ADD COLUMN deployed_version TEXT;
-- Backfill from the finished runs: the newest sealed version a run completed.
UPDATE secrets s SET deployed_version = (
    SELECT v.provider_version FROM secret_versions v
      JOIN rotation_runs r ON r.org_id = v.org_id AND r.secret_id = v.secret_id
                          AND r.new_version = v.provider_version AND r.state = 'done'
     WHERE v.org_id = s.org_id AND v.secret_id = s.id
     ORDER BY v.seal_seq DESC LIMIT 1);

-- +goose Down
ALTER TABLE secrets DROP COLUMN deployed_version;
ALTER TABLE secret_versions DROP CONSTRAINT secret_versions_seal_seq_unique;
ALTER TABLE secret_versions DROP COLUMN seal_seq;
