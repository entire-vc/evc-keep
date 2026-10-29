# Local carrier discovery

`internal/runner/discover` scans temporary or deployed files only when a
trusted local host policy grants a read. It has no transport, alerting,
credential issuance or revocation behavior.

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

The XML standard-library decoder retains an internal CharData buffer that cannot
be explicitly wiped by this package. This is a residual in-process memory risk;
the owned XML tree, decoded entries and input buffers are wiped, but this is not
a guarantee of erasing every copy made by the runtime or standard library.

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
