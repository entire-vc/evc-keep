# Security Policy

Keep stores and delivers secrets. We take any report about it seriously
and ask that you report privately rather than through a public issue.

## Reporting a vulnerability

**Do not open a public issue for a suspected security vulnerability.**

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/entire-vc/evc-keep/security/advisories/new)**

The report is visible only to the maintainers of this repository until
we publish an advisory. If you cannot use GitHub, email
<support@entire.vc> with `SECURITY` in the subject and we will move the
conversation somewhere private — please don't put vulnerability details
in a public issue in the meantime.

Please include:
- a description of the vulnerability and its impact;
- steps to reproduce, or a proof of concept if you have one;
- the version / commit you tested against;
- a suggested fix, if you have one.

### What to expect

1. **Acknowledgment** — we aim to respond within 48 hours.
2. **Assessment** — we investigate and assess severity.
3. **Fix** — we develop and test a fix.
4. **Disclosure** — we coordinate disclosure timing with you.

## Scope

In scope: this repository's code — `keep` (CLI), `keep-server`,
`keep-runner`, and the storage providers under `pkg/provider`.

Out of scope: third-party secret backends themselves (1Password, Vault,
cloud KMS, etc.) — report those to their own maintainers; feel free to
also let us know so we can track and mitigate on our side.

## Supported versions

This project is pre-alpha: there are no tagged releases yet, and only
the `main` branch is supported. This section will list supported
release lines once versioned releases begin.
