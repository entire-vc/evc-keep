-- +goose Up
-- exec_with_secret on the server. A template is policy: the organization
-- registers it once, with the digest the runner compares against its own
-- copy. A request freezes the template id, digest, network mode, destinations
-- and parameters next to the usual references; a network template never gets
-- a job row before a human approves exactly those destinations. Metadata
-- only: no value, no command output.
CREATE TABLE exec_templates (
    org_id UUID NOT NULL REFERENCES organizations(id),
    template_id TEXT NOT NULL CHECK (template_id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    template JSONB NOT NULL,
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (org_id,template_id)
);

-- NULL for a deployment request; the frozen exec snapshot for an exec one
-- (its target stays '{}'). deployment_requests_frozen already forbids edits.
ALTER TABLE deployment_requests ADD COLUMN exec JSONB;

-- +goose Down
ALTER TABLE deployment_requests DROP COLUMN exec;
DROP TABLE exec_templates;
