// Package targets writes a secret value into one of a closed set of local
// file-based targets on a runner host (ADR-001 §3.2, Appendix C.5; threat
// model §2.3 T, I; R-DEP-3, R-POL-4, S-4). There is no network target and
// there must never be one (R-POL-3): a value leaves this package only
// through the file it was asked to write.
//
// Write is symlink-safe by construction: every path component, from the
// filesystem root to the target's own directory, is opened with openat and
// O_NOFOLLOW, one component at a time, so a symlink anywhere on the path —
// or a directory swapped for one between two of our own operations — is
// rejected rather than followed. The target itself is never opened
// directly for writing; Write creates a fresh, exclusively-owned temporary
// file in the target's directory, fsyncs it, and renames it over the
// target's name with renameat against the held directory descriptor, so the
// rename cannot be redirected by a later change to the path.
//
// Write refuses a target, or any directory on its path, that is readable or
// traversable by an agent's uid or gid (R-POL-4): a value written where an
// agent can read it has reached the agent regardless of what the runner
// protocol's own declarative checks (pkg/runnerproto, HostPolicy.Check) say
// about the job. That check is declarative, over the fields the server
// signed; this one is against the filesystem's own truth at write time,
// which is why both exist.
//
// The same refusal covers what mode bits cannot show: on Linux, a POSIX ACL
// (access or default) on the target's directory or on the temporary file; on
// macOS, an extended ACL on the directory. An existing target is read only if
// it is a regular file with one link, owned by the runner or the consumer —
// otherwise a hardlink to another service's secret file would be folded into
// this one's. Write's first step is runnerproto.Target.Validate, so a Field
// or Unit of the wrong shape is refused before anything is read or written.
//
// An existing target that a kind folds into its new content (env-file,
// launchd-env, mcp-config, hermes-config) must also not be writable by
// anyone, by an agent group or through an ACL: an agent that could write it
// could have planted an argv entry, a command or an environment line that
// the write would carry into a file the agent can no longer touch. A kind
// that replaces the file wholesale (file, systemd-credential) never reads it
// for content and is not held to that. On macOS the built-in group
// "everyone" (gid 12) counts as an agent group.
//
// env-file writes POSIX-shell assignment syntax: a value of safe characters
// is written bare, anything else single-quoted (a single quote inside is
// written as close-quote, backslash, quote, open-quote), so a consumer that
// sources the file reads exactly the value. Readers that do not
// follow shell rules (docker --env-file, systemd's EnvironmentFile) are not
// covered. launchd-env finds the EnvironmentVariables dict by tokenizing the
// plist, not by a text search, and edits only inside it. The JSON kind
// (mcp-config) replaces only a string, null or absent leaf; an object or
// array at the field is refused.
//
// hermes-config is one NAME=value line in $HERMES_HOME/.env, written like
// env-file's, for Hermes's own loader: config.yaml refers to the variable as
// ${NAME}. The loader rewrites the file, parses it with python-dotenv and
// strips non-ASCII from credentials, so a value that any of those would lose,
// change or echo (outside printable ASCII, a quote of either kind, a
// backslash, a ${ reference, a variable name directly before an equals sign)
// is refused, with one message for all of them.
//
// systemd-credential runs systemd-creds only from the fixed path
// /usr/bin/systemd-creds, and only if it is a plain file owned by root and
// not writable by group or others, with an empty environment; PATH is never
// consulted. On macOS, HostPolicy path prefixes must be written under
// /private (/etc, /var and /tmp are symlinks there, which this package
// refuses like any other symlink on a path).
//
// This package is part of the plaintext zone (pkg/secret's doc comment):
// only it, pkg/fingerprint, pkg/provider, internal/builtin and
// internal/runner may call secret.Expose.
package targets
