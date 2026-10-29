# Creating the first organization: `keep-server bootstrap-org`

A fresh Keep server has no organization and so no admin token. Calls such as
`POST /mesh/install` and token issuance need that token. `bootstrap-org` is the
supported way to get both, on the host, once.

```
KEEP_DATABASE_URL=... KEEP_ROOT_KEY_FILE=... \
  keep-server bootstrap-org --name <org name> --admin-email <email> \
    --token-file /abs/path/admin.token --ttl <duration>
```

Example, a token valid for 7 days:

```
keep-server bootstrap-org --name acme --admin-email ops@acme.example \
  --token-file /etc/keep/admin.token --ttl 168h
```

It uses the same code as an ordinary creation: the organization row, its CA and
job-signing key (sealed under the server root key), the builtin store `default`
bound at the organization scope, the admin user with the `admin` role at the
organization scope, and a journal record `org.bootstrap`.
The journal record is written before the token is issued and stands for that
issuance too: there is no separate `identity.token_issue` record.

- stdout: `org_id=<uuid>` and `token_file=<path>`. Nothing else; the token
  expires `--ttl` after the command ran.
- `--ttl` is required: a Go duration, positive and at most `720h` (30 days).
  Missing, zero, negative or longer is refused (`error_class=invalid_argument`)
  before anything is created.
- The token is only in the file: mode `0600`, `--token-file` must be absolute,
  and an existing file is never overwritten. It is written via a temp file in
  the same directory and linked into place. The token is not in stdout,
  stderr, logs, errors or the journal.
- A name that already exists is refused (`error_class=already_exists`); no
  second organization is created. The name check and the insert run in one
  transaction under `LOCK TABLE organizations IN SHARE ROW EXCLUSIVE MODE`, so
  two concurrent runs with the same name cannot both succeed.
- Needs the schema at version 40 or later (`keep-server migrate up`).

## The default store

Creating a secret needs a store bound at its scope or at one of its ancestors;
without one `POST /orgs/{org}/secrets` answers `409 no_store_bound`.
`bootstrap-org` binds the builtin store `default`, owned by the organization
scope, in one transaction with the store itself, so a secret with
`provider_ref` `builtin://default/<name>` can be created right away.

An organization created before `bootstrap-org` did this has no store. Bind one
without recreating the organization:

```
KEEP_DATABASE_URL=... keep-server bind-default-store --org-id <org_id>
```

stdout is one line, `org_id=<uuid> store_id=<uuid> binding=created|exists`.
It is safe to repeat: if the organization scope already has a binding, to
`default` or to any other store, nothing changes and it prints
`binding=exists`. An existing `default` store without a binding is bound, not
duplicated; a disabled one is refused. An unknown organization is refused with
`error_class=not_found`. Each run writes a journal record `store.bind_default`
with the store id and the outcome. The record is written after the binding: if
writing it fails, the command exits non-zero and a repeated run records
`binding=exists`.

When to use it: first start of a server, or a new organization on a server you
administer. Not for day-to-day operation: later tokens come from the token API
with this admin token.

Move the token file to where its consumer reads it and keep it out of
shared locations.

Replacing a leaked token depends on its kind:

- Agent and service tokens are replaced through the token API: revoke the
  leaked one (`POST /orgs/{org_id}/tokens/{token_id}/revoke`) and issue a new
  one (`POST /orgs/{org_id}/tokens`).
- The admin token printed by `bootstrap-org` cannot be replaced that way: the
  token API issues only agent and service tokens, and revoking the admin token
  would leave the organization without an admin. If the organization holds no
  secrets and no runners yet, remove it as described in
  [Rolling back](#rolling-back) and run `bootstrap-org` again. For an
  organization that already holds data there is no supported path yet; ask the
  Keep owner.

## Rolling back

Code: revert the MR. Data: an organization created by mistake and not yet
used (no secrets, no runners) is removed in one transaction. The journal rows
stay: the journal is append-only and its chain remains verifiable.

```sql
BEGIN;
DELETE FROM tokens      WHERE org_id = '<org_id>';
DELETE FROM store_bindings WHERE org_id = '<org_id>';
DELETE FROM stores      WHERE org_id = '<org_id>';
DELETE FROM memberships WHERE org_id = '<org_id>';
DELETE FROM org_ca      WHERE org_id = '<org_id>';
DELETE FROM users       WHERE org_id = '<org_id>';
DELETE FROM keep_kek    WHERE org_id = '<org_id>';
DELETE FROM organizations WHERE id = '<org_id>';
COMMIT;
```

An organization that already holds secrets or runners is not removed this
way: its rows reference the tables above, and the statement fails on the
first constraint. Do not disable constraints; ask the Keep owner.

If the command fails after the organization was created, it prints
`org_id=<uuid> left behind` on stderr: remove it as above and run again. A
token issued but not written to the file is revoked before the command exits.

If the process was killed mid-run (power loss, `SIGKILL`), a `.keep-token-*` or
`.keep-bootstrap-*` file may remain next to `--token-file`; it is `0600` and
may hold a valid token. Delete it, then remove the organization as above.
