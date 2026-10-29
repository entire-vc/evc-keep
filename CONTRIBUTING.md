# Contributing to Keep

Keep exists to keep a secret's *value* out of places it shouldn't be.
Every rule below exists in service of that one property. They apply
equally to a human contributor and to an AI coding agent working on
this codebase — nothing here is softer for one than the other.

## The rule that isn't negotiable

**A secret's value must never appear in:** application logs, test
output, API responses, MCP tool output, error messages, panic traces,
CI job output, or a code comment / commit message / issue / PR
description.

What *is* safe to log, return, or print: the secret's **name**,
**version**, and a keyed **fingerprint** (HMAC over the value, never the
value or a plain hash of it) — never the value, never its length in a
form that materially narrows the search space, never a prefix/suffix.

If you're not sure whether something you're about to print counts as
"the value" — assume it does, and find another way to say what you were
trying to say.

## Write the leak test before the feature

Any change that touches a secret's value in memory — a new provider, a
new API endpoint, a new log statement near secret-handling code — ships
with a test that asserts the value does **not** appear in the surface
you're touching (log output, response body, error string), and that
test must fail on the old code and pass on the new one.

This is written first, not added after the feature works. A feature
that "should" not leak a value and a feature that's been shown not to
is a different level of confidence, and this project only ships the
second kind.

The same standard applies to any check you add for another reason:
before trusting a green run, show that the same check goes red on a
deliberately bad input. A check that has never been observed to fail
is indistinguishable from a check that can't.

## Before you open a merge request

- `make lint` — gofmt, `go vet`, `golangci-lint`.
- `make race` — `go test -race ./...`.
- Mutation checks (`scripts/check-*-mutations.sh`): run locally only
  the ones your diff touches, listed by `scripts/mutations-for-diff.sh`.
  Follow [the local PostgreSQL procedure](#local-mutation-checks-with-postgresql)
  to reset the database before each script. Shared files (`go.mod`, the
  linter config, the mutation helpers) select all of them.
  Mutation checks are not a merge condition: a merge request pipeline
  creates no mutation job (security, lint, tests and the build are what it
  must pass). Every mutation job runs in the nightly schedule, which covers
  what each merge brought to `main` (the browser mutation suite also runs
  on every push to `main`), and on a release tag, where the
  `release` job waits for all of them: a red mutation suite stops the release,
  not your merge request. A red nightly is fixed like a red `main`.
- Before waiting on CI, look at the pipeline of `main`. If `main` is red,
  your merge request will not go green for reasons that are not yours:
  depend on the fix for `main` instead of re-running CI.
- A re-review after changes requested covers the fix diff only, not the
  whole merge request again.
- CI also runs a secret scanner over your diff (gitleaks). It fails
  closed: if you need a fixture that looks like a real credential (e.g.
  a provider conformance test), add it to the allowlist in
  `.gitleaks.toml` with a comment explaining why it's fake, rather than
  disabling the scan.
- Tool-specific instruction files are not part of this repository (see
  `.gitignore`) — this project's contributor norms live entirely in
  this file and in `SECURITY.md`, so that they're the same for every
  contributor regardless of what tooling they use.

### Local mutation checks with PostgreSQL

Database-backed mutation checks need a fresh database before **each
script**, not just before the loop. Mutants and tests can change schema
constraints, grants and rows; copying the source tree does not restore
PostgreSQL state. A successful migration command against an existing
database also does not undo changes to an already-applied migration.

Use a dedicated, disposable PostgreSQL instance. The example below uses
fake test credentials and runs two database-backed suites. Choose an
unused localhost port and container name; never point this reset loop at
a database containing data you want to keep.

```sh
(
    set -eu
    mutation_container=keep-mutation-tests
    mutation_port=55432
    docker run -d --name "$mutation_container" \
        -e POSTGRES_USER=keep -e POSTGRES_PASSWORD=keep -e POSTGRES_DB=keep \
        -p "127.0.0.1:$mutation_port:5432" postgres:17
    trap 'docker rm -f "$mutation_container" >/dev/null' EXIT
    export KEEP_DATABASE_URL="postgres://keep:keep@127.0.0.1:$mutation_port/keep?sslmode=disable"

    attempts=0
    until docker exec "$mutation_container" pg_isready -U keep -d postgres -q; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 30 ] || exit 1
        sleep 1
    done

    for script in scripts/check-audit-mutations.sh scripts/check-builtin-mutations.sh; do
        docker exec "$mutation_container" dropdb --if-exists --force -U keep keep
        docker exec "$mutation_container" createdb -U keep keep
        go run ./cmd/keep-server migrate up
        "$script"
    done
)
```

For your change, replace the two example paths with
`$(scripts/mutations-for-diff.sh)` and keep the reset and migration inside
the loop. Each script must exit successfully and report a green baseline;
a timeout, skipped database test or red baseline is not a passing run.
The subshell stops on the first failure and removes its test container.
CI already provisions a separate PostgreSQL service for each job; this
local procedure does not change CI behavior.

## Public repository

This repository is public. Code, comments, test names, error messages,
scripts, CI config and commit messages are written in English and carry
no internal planning labels (milestone or wave numbers).
`scripts/check-public-hygiene.sh` enforces it in CI; run it before you
push. `docs/` is not scanned. When a test genuinely needs a non-Latin
character (a homoglyph host, say), write it as an escape
(`"\u0430pi.example.com"`); only if that is impossible, put
`public-hygiene:allow` on that line with the reason next to it. The
marker excuses that one line, never the rest of the file or a file name.

What the check rejects:

- Cyrillic in file contents and in tracked file names, across the
  Cyrillic blocks (U+0400-U+052F, U+1C80-U+1C8F, U+2DE0-U+2DFF,
  U+A640-U+A69F).
- Internal wave labels: the letter `W`, digits, a `.` or `_`, digits
  (`W<n>.<n>`, `W<n>_<n>`, any number of digits). A label is not shielded
  by a preceding underscore or a `Test`/`Benchmark`/`Fuzz`/`Example`
  prefix, so `Test_W<n>_<n>` is caught; a label glued to a preceding
  capital letter or digit is not a label.
- The same two rules in commit messages (subject and body) and, in a
  merge-request pipeline, in the merge request title and description:
  with squash they become the commit message on `main` and reach the
  public mirror. In a merge-request pipeline a missing or empty commit
  range fails the job instead of passing silently, and so does a
  description over 2700 characters (CI truncates it, so it cannot be
  checked in full).

Binary files are not scanned: a tracked binary is not text a reader sees
in a diff, and arbitrary bytes would trip the Cyrillic check by chance.

## CI coverage for documentation changes

The security scanner, its finding selftests and public hygiene remain in the
parent pipeline. The full Go test matrix and browser checks run in a
dependent child pipeline, so a failed child fails the parent; the mutation
suites of the browser checks run after review, with the other mutation jobs
(see above).

An MR can omit those heavy jobs only when its complete diff modifies
existing regular files in the explicit documentation list in
`scripts/generate-test-pipeline.py`. New, deleted, renamed, executable or
symlink paths, mixed changes and an unavailable diff run full coverage.
The default branch, scheduled and manually started pipelines always run
full coverage. Set `KEEP_FULL_CI=1` to force it in an MR as well.
Full mutation set: daily schedule on main and every release tag.

A push to any other branch runs only the security stage (the secret scan
and its selftests). Full coverage for that commit comes from its MR
pipeline, so a branch is not tested twice when the MR is opened right
after the push (the open-MR workflow rule only sees MRs that already
exist). To test a branch before it is ready for review, open a draft MR
or start a pipeline for the branch manually.

Run `python3 scripts/test_ci_config.py` (with PyYAML installed) when
changing the CI configuration or selector. The checks include negative
controls for every security stage and the docs-only classification.
With an authenticated `glab`, run
`python3 scripts/check-ci-dry-run.py <unprotected-ref>` (a branch with no open MR) to validate the
expanded job sets against GitLab without creating pipelines. Identical
generated configurations reuse one lint response.

## Review and merge

`main` is protected: every change lands through a merge request, and no
one pushes to it directly — including a maintainer authoring their own
code. No one merges their own security- or provider-affecting change
without an independent review having looked at it first.

A change that touches the secret value path (`pkg/secret`, providers,
the plaintext zone, anything that answers outward) gets a leak review,
and a change to cryptography (sealer, fingerprint, job signing and
delivery) gets a crypto review, **before** it is sent to the maintainer.
Paste each reviewer's verdict into the merge request. Findings from the
maintainer's review are fixed on the same branch and in the same merge
request; only a finding outside the change's scope becomes a separate
issue.

Keep merge requests small and focused, and describe what changed and
how you tested it — the acceptance criterion for a change is the
command you ran and the output you got, not "should work now".

## Reporting a vulnerability

Do not open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md).
