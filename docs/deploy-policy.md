# Deployment policy

A deployment request (`keep deploy`), or a request to run a command on a host
with a secret, runs without a person only when the organization's deployment policy has a
rule for it. Without a matching rule the request waits for approval by someone
other than the requester. This page is for operators of a Keep server.

## What a rule admits

A policy is a JSON object with three independent lists:

```json
{
  "rules": [
    {
      "secret_id": "<secret uuid>",
      "runner_id": "<runner uuid>",
      "kind": "file",
      "path_prefix": "/var/lib/app/ext"
    }
  ],
  "exec_rules": [
    {
      "secret_id": "<secret uuid>",
      "template_id": "<exec template id>",
      "labels": {"environment": "staging"}
    }
  ],
  "adoption_rules": [
    {
      "secret_id": "<secret uuid>",
      "runner_id": "<runner uuid>",
      "kind": "yaml-scalar",
      "path": "/srv/app/config.yaml",
      "field": "service.token"
    }
  ]
}
```

- `rules[]` admits one secret to one target kind (`file`, `env-file`, …) under
  `path_prefix` (the target path must be below it, not equal to it).
- `exec_rules[]` admits one command template (`template_id`) with one secret. A template that
  declares network access always waits for a person.
- `adoption_rules[]` admits one read-only YAML adoption by the exact
  `secret_id`, `runner_id`, `kind`, `path` and `field`. It has no prefix or
  label selector. Deployment and exec rules do not grant adoption.
- Deployment and exec rules name their hosts by `runner_id`, by `labels` (`environment`:
  `development|staging|production`, `platform`: `linux|darwin`), or both; both
  must then match. A rule with neither is refused.
- `secret_id` is always required: there is no organization-wide wildcard.
- A `prod` secret still needs a person the first time it is deployed to a
  target and for every exec, and is never delivered to a host that shares a
  uid or has unknown attributes, whatever the policy says.
- Every `prod` adoption requires a fresh human approval and the same host
  restrictions. An unlisted adoption also needs approval. The runner must
  independently permit that exact path/field in `adoption_targets` and allow
  reading it in `targets`; see [YAML adoption](yaml-carrier-adoption.md).

At most 128 entries in each list. YAML has no deployment or rotation writer.

## Setting the policy

Run on the server host, with the database the server uses:

```
KEEP_DATABASE_URL=... keep-server set-deploy-policy --org-id <org_id> --policy-file policy.json \
    [--max-deploys-per-hour N] [--expect-revision N] [--dry-run]
```

- The file replaces the whole policy. To add a rule, start from the current
  policy and add to it.
- The file must contain exactly one policy object with known fields only.
- Every `secret_id` must be a secret of this organization and every
  `runner_id` an enrolled runner of this organization.
- `--max-deploys-per-hour` (1..1000) sets the organization's rate limit; left
  out, the current limit stays (10 for an organization without a policy).
- `--expect-revision N` writes only if the stored revision is `N` (`0`: no
  policy yet). Use it to avoid overwriting a change made in between.
- `--dry-run` checks the file and prints the result and the change without
  writing anything.

stdout is two lines:

```
org_id=<uuid> revision=<n> rules=<k> exec_rules=<e> adoption_rules=<a> max_deploys_per_hour=<m>
change: revision=<a>-><b> max_per_hour=<x>-><y> +<added rule> -<removed rule> …
```

A rule is shown by its key, `secret_id/runner_id|labels/kind/path_prefix`
(exec rules: `exec:secret_id/runner_id|labels/template_id`; adoption rules:
`adopt:secret_id/runner_id/kind/path/field`). A long change is
cut with a count of the rules not shown.

Each stored change writes one journal record `deploy.policy_set` in the same
transaction as the policy, with the `change:` text as its reason. Secret
values and fingerprints never appear in the policy, the output or the record.

A refusal prints `set-deploy-policy failed: error_class=<class>: <message>`
and exits non-zero; nothing is written:

| class | cause |
|---|---|
| `invalid_argument` | unreadable or malformed file, unknown field, a rule failing validation, a secret or runner of another organization, a limit outside 1..1000 |
| `conflict` | `--expect-revision` does not match the stored revision |
| `not_found` | no such organization |

Needs the schema at version 59 or later (`keep-server migrate up`).
