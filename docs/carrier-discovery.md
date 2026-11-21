# Local carrier discovery

`internal/runner/discover` scans temporary or deployed files only when a
trusted local host policy grants a read. The package itself has no transport,
alerting, credential issuance or revocation behavior; the server and the CLI
connect it as described under "Running a discovery".

Provide an absolute canonical root, finite-depth relative glob rules,
format kinds, exact variable-name allowlists, an explicit `TrustedUIDs` list,
and positive byte/file limits. The trusted local host policy authenticates these
writer identities; never include an untrusted caller's UID. Empty owner admission
fails closed. The scanner does not infer that the invoking user's ownership is trusted.
`..`, absolute globs, `~` and recursive `**` are refused. Each credential
file has one name supplied by policy. A name found in file contents cannot
become output metadata unless it matches that allowlist.

On Unix, directories and files are opened relative to pinned directory
descriptors with `O_NOFOLLOW`. Symlinked roots, parents and leaves,
hardlinked files, nonregular files, and group/other-writable carrier files,
roots, root ancestors or intermediate directories are refused. Even a sticky,
world-writable temporary directory is refused as a root ancestor. The policy root
and its ancestors must also be protected from the untrusted caller's owner-level
write access. Every root ancestor, root, relative directory and carrier file
must be owned by a listed trusted UID as well as satisfy the mode checks. The host
policy also owns ACL protection and scheduling limits. Other platforms
fail closed. A file already larger than the byte limit is rejected before
any data read; growth beyond the limit also fails. Concurrent mutation by
the authorized owner is not a snapshot guarantee.

Each glob rule examines at most `64 * MaxFiles` directory entries, counting
unmatched names across all wildcard levels. Exceeding this budget fails the whole
scan with a fixed policy error instead of returning an incomplete inventory.

Supported formats:

- Env files: literal `NAME=value`, single/double quotes, literal quote
  concatenation and `export NAME=value`. Shell expansion, commands,
  ambiguous whitespace after `=`, multiline values and unsupported escapes
  fail closed. This is a conservative literal subset, not a shell evaluator
  or a general dotenv dialect interpreter.
  Inside double quotes, only escaped backslash, double quote, dollar and
  backtick are accepted. Escaped spaces, tabs and single quotes are refused
  there; unquoted escaped whitespace remains supported.
- Launchd: XML and `bplist00` property lists, reading string entries from
  `EnvironmentVariables`. Binary object sizes/references and UTF-16
  surrogate pairs are checked before decoding.
- Systemd units: literal `[Service]` `Environment=` assignments, including
  resets and common C escapes. Repeated assignments to the same permitted
  variable without an intervening empty `Environment=` reset are unsupported
  and fail the complete scan with `ErrParse`; this parser does not resolve
  systemd assignment precedence. Specifier expansion and unsupported escapes
  fail closed. `EnvironmentFile` and `LoadCredential` references are never
  followed implicitly; add separate permitted env-file or credential rules
  for those paths. Credential files are fingerprinted as exact bytes,
  including trailing newlines; encrypted credentials require materialization
  into a separately permitted plaintext credential file first.
- MCP: string entries under `mcpServers.<server>.env`. Duplicate JSON keys,
  nonstring environment values and invalid Unicode are refused. Conflicting
  instances of the same permitted variable name in one file are ambiguous
  and refused.
- YAML (`yaml-scalar`): explicitly permitted dotted mapping paths such as
  `service.token`, preserving the complete selector as the finding name.
  The selected leaf must be a string. A single mapping-root document is
  limited to 1 MiB, depth 32 and 16,384 nodes; duplicate or complex keys,
  aliases, anchors, merge keys, explicit tags, multiple documents and
  ambiguous/non-string selection fail the whole scan. See
  [YAML adoption](yaml-carrier-adoption.md#yaml-semantics-and-limits) for
  selector syntax and the identical adopt/verify reader.

The XML standard-library decoder retains an internal CharData buffer that cannot
be explicitly wiped by this package. This is a residual in-process memory risk;
the owned XML tree, decoded entries and input buffers are wiped, but this is not
a guarantee of erasing every copy made by the runtime or standard library.
The YAML decoder also retains immutable scalar strings until Go collects
them. Owned byte buffers are wiped; runtime copies cannot be erased reliably.

Values are decoded into mutable buffers, copied into `secret.Value` for
`pkg/fingerprint.Compute`, and wiped. Superseded buffer storage is wiped
before growth. Finding's closed schema is `Path, Name, Fingerprint, Len`;
paths are relative to the policy root and must contain only printable Unicode characters. Errors are fixed templates with no
file bytes, parser diagnostics or unwrap chains. The scanner emits no logs. Future remote adapters must collapse parse and read
failures into one outward error class: literal syntax rejection can otherwise
reveal one bit about a value. No remote adapter is implemented here.
The caller supplies the correctly authenticated tenant fingerprint key and
owns its lifetime; the scanner does not wipe a borrowed key.

A missing permitted file contributes no finding; an unavailable root,
unsafe path or unreadable file is a scan failure.

`Scan` returns the complete inventory or a fixed error with no partial
findings. Do not call `Compare` after a failed scan: a read failure is not
proof of absence. `Compare` requires the caller's authenticated tenant `fingerprint.Key` and validates it even for an empty
inventory. Every finding and known carrier must use that expected key ID; the
first submitted fingerprint is never a trust anchor. Matching path/name and full fingerprint means
`match`; a changed fingerprint means `stale`; an unregistered path/name means
`sprawl`. A missing known carrier of an active account means `unknown_find`;
missing inactive carriers contribute no observation. This result never recommends reissue.

Run `go test -race -count=1 ./internal/runner/discover/...` and
`./scripts/check-discovery-mutations.sh`. Tests use generated local files;
no host configuration or running service is inspected.

The mutation check instruments only its disposable source copy to retain byte
backing arrays at allocation and growth (before cleanup). Tagged lifecycle tests
assert zero contents after successful scans and parse/read failures. The original
production tree contains no observer or test callbacks. Python 3 is required to
prepare that test copy.

## Running a discovery

An organization admin (right `manage_runners`) asks one enrolled runner to look
at its own host and compare what it finds with the carrier registry:

```
keep carriers discover --runner RUNNER_ID --store STORE_ID [--wait 1m] [--json]
```

`STORE_ID` is an organization-owned builtin store; its fingerprint key is sealed
to the runner for this one request, so a finding is a keyed fingerprint, never a
value. The caller supplies no path and no rule: the runner's own
host policy owns them. A runner runs one discovery at a time and at most
`MaxDiscoversPerHour` are accepted per runner.

Each finding has one verdict:

| Verdict | Meaning |
|---|---|
| `match` | a registered carrier holds the current version |
| `stale` | a registered carrier holds another value |
| `sprawl` | a permitted name in a place no carrier is registered for; an incident when it holds a value this store issued (the fingerprint of any version of its secrets) |
| `unknown_find` | a registered carrier of an active secret that the complete scan did not find (incident) |

A finding line carries `verdict`, `carrier_id` (for `match`, `stale` and
`unknown_find`), `path`, `name`, `fingerprint` (for `match`, `stale` and
`sprawl`) and `incident`. No line carries the value or how many bytes it has,
for any verdict: the size of a value Keep does not know would narrow a guess at
it.

A carrier is compared by its path and the name a scan reports: the variable
name for `env-file`, and for `mcp-config` the variable at the end of its
registered field `mcpServers.<server>.env.<VAR>`. A scan reads an MCP file's
env keys without the server, so two servers of one file with the same
variable are one place: one finding there accounts for both. An `mcp-config`
carrier whose field is not of that form matches no finding, so a complete scan
always reports it as `unknown_find`.
For `yaml-scalar`, the finding name is the entire registered dotted field,
so `service.token` and `other.token` remain different places. A successful
adoption followed by an unchanged read produces `match`; changing that scalar
produces `stale`. Adoption provenance does not bypass discovery's read policy.

An `unknown_find`, and a `sprawl` holding an issued value, open an incident for
a person (the line's `incident` is true and it stays open in the report).
Discovery never rotates or redeploys anything by itself. Exit codes: 0 all
matches, 1 findings, a failed run or pages that do not add up (below), 4 report
still pending (read it later with the same request id over
`GET /orgs/{org_id}/carriers/discover/{request_id}`).

One discovery compares with at most 1024 registered carriers of the store on
the runner's host. A larger registry is refused with `invalid_argument` ("too
many registered carriers for one discover"); if the registry grows past the
bound while the scan runs, its report is rejected and the run fails. Every
carrier registration accepts (a target path of up to 4096 characters, a field
of up to 256) is compared. A report therefore holds at most 4096 findings plus
1024 `unknown_find` lines.

### Reading a report in pages

A completed report is read in pages of at most 4096 lines, in the order path,
name; the server sets the page size. Every answer carries `offset` (the line
the page starts at) and `total` (the lines of the whole report).
`GET /orgs/{org_id}/carriers/discover/{request_id}?offset=N` reads the page at
line `N`, a decimal number from 0 to `total` without sign or leading zero;
anything else, `N` past `total` included, is `400 invalid_argument`. `POST`
answers the first page. `ok` is the whole report's: a first page of matches
says `ok: false` when a later page holds any other verdict. A report gets no
lines after its run completes, so an offset names the same line on every read.

`keep carriers discover` reads the pages one after another, each under its own
64 MiB bound, and prints them as they come; with `--json` it prints one
document with every page's findings and the report's `total`. An empty page
before `total`, a `total` that changes between pages, a page that does not start
where it was asked or holds more lines than are left, or a report that is no
longer completed ends the run with exit 1 and `bad_response`; such a run is
never reported clean.
