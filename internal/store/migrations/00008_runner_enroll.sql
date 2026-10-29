-- Runner registration: one organization CA, one-time enrollment
-- tokens, and the registered runners themselves. ADR-001 §3.2, threat model
-- §2.3 (S, E).
--
-- org_ca holds two sealed private keys per organization (the CA itself and
-- the job-signing key — pkg/runnerproto.Signer), both wrapped through
-- internal/builtin/sealer the same way any other built-in secret is: a
-- KEK id, a wrapped DEK, and a ciphertext. Neither private key is ever
-- stored in the clear; ca_cert_der and sign_pub_key are the two PUBLIC
-- halves and hold no secret material.
--
-- enroll_tokens stores only a token's SHA-256 hash (see internal/identity's
-- tokens table for the same convention) plus what the token is bound to:
-- the expected host and a SHA-256 of the host policy the admin declared at
-- issuance — keep-runner enroll must present the same policy hash, or the
-- token is refused, however valid it otherwise is.
--
-- runners is the registry of enrolled runners; revoked_at is checked on
-- every mTLS request (internal/runnerauth) — no CRL/OCSP, since org_id and
-- runner_id are only ever trusted once a request's client certificate has
-- already verified against org_ca.ca_cert_der.
--
-- +goose Up
CREATE TABLE org_ca (
    org_id           UUID PRIMARY KEY REFERENCES organizations(id),
    ca_cert_der      BYTEA NOT NULL,
    ca_kek_id        TEXT  NOT NULL REFERENCES keep_kek(id),
    ca_wrapped_dek   BYTEA NOT NULL,
    ca_ciphertext    BYTEA NOT NULL,
    sign_key_id      TEXT  NOT NULL,
    sign_pub_key     BYTEA NOT NULL,
    sign_kek_id      TEXT  NOT NULL REFERENCES keep_kek(id),
    sign_wrapped_dek BYTEA NOT NULL,
    sign_ciphertext  BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE enroll_tokens (
    id            UUID PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES organizations(id),
    token_hash    BYTEA NOT NULL,
    last4         TEXT  NOT NULL,
    host          TEXT  NOT NULL,
    policy_sha256 TEXT  NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    UUID NOT NULL,
    UNIQUE (token_hash),
    FOREIGN KEY (org_id, created_by) REFERENCES users (org_id, id)
);
CREATE INDEX enroll_tokens_org_id_idx ON enroll_tokens (org_id);

CREATE TABLE runners (
    id             UUID PRIMARY KEY,
    org_id         UUID NOT NULL REFERENCES organizations(id),
    host           TEXT NOT NULL,
    cert_serial    TEXT NOT NULL,
    cert_not_after TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, id)
);
CREATE INDEX runners_org_id_idx ON runners (org_id);

ALTER TABLE enroll_tokens
    ADD CONSTRAINT enroll_tokens_policy_sha256_shape
        CHECK (policy_sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE org_ca
    ADD CONSTRAINT org_ca_sign_pub_key_len
        CHECK (octet_length(sign_pub_key) = 32); -- Ed25519 public key

-- internal/enrolltoken's issuance event: registeredActions in
-- internal/audit/record.go and this list must stay identical —
-- TestActionRegistryMatchesMigrationCheck checks that on every run. This is
-- the migration that runs last, so it is the one whose text actually reaches
-- the live constraint — it re-declares 00006_audit_token_actions.sql's list
-- in full, plus runner.enroll_token_issue.
ALTER TABLE audit_records
    DROP CONSTRAINT audit_records_action_closed,
    ADD CONSTRAINT audit_records_action_closed
        CHECK (action IN ('secret.create_ref', 'secret.input', 'secret.deploy', 'secret.disable',
                          'runner.enroll', 'runner.enroll_token_issue', 'exec.run', 'kek.purge',
                          'org.key_level.changed', 'org.key_level.change_denied',
                          'org.key_level.change_failed',
                          'identity.token_issue', 'identity.token_revoke'));

-- +goose Down
ALTER TABLE audit_records
    DROP CONSTRAINT audit_records_action_closed,
    ADD CONSTRAINT audit_records_action_closed
        CHECK (action IN ('secret.create_ref', 'secret.input', 'secret.deploy', 'secret.disable',
                          'runner.enroll', 'exec.run', 'kek.purge',
                          'org.key_level.changed', 'org.key_level.change_denied',
                          'org.key_level.change_failed',
                          'identity.token_issue', 'identity.token_revoke'));

DROP TABLE runners;
DROP TABLE enroll_tokens;
DROP TABLE org_ca;
