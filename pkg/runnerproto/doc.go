// Package runnerproto is the contract between Keep Server and a runner:
// the signed job, the one-time delivery of a builtin value to the runner,
// the closed result, and the host's local policy. It holds types and checks
// only; transport lives elsewhere.
//
// Nothing here ever carries a secret value. A job names a secret and states
// the version and fingerprint it expects; a result reports a fingerprint,
// never bytes. The package does not import pkg/secret, and a lint rule
// (runnerproto-no-plaintext in .golangci.yml) keeps it that way.
//
// The flow for one deploy of a builtin secret:
//
//  1. The server builds a Job, encodes it canonically and signs it with
//     Ed25519 (Signer). The runner pulls the SignedJob over mTLS.
//  2. The runner calls VerifyJob: signature against its pinned server keys,
//     then its own org and runner id, then the time window, then the replay
//     journal. Only then does it parse anything the job says.
//  3. The runner calls Check against its HostPolicy, independently of the
//     server: a server that allows a target does not make it allowed here.
//  4. For a builtin secret the value is not in the job. The runner sends a
//     ValueRequest naming only the job id; the server releases the value
//     once (CheckRelease), sealed with HPKE to the runner's key, with Info
//     binding the ciphertext to that job.
//  5. The runner reports a Result: ok, fingerprint, version, healthcheck,
//     error class. Nothing else fits in it.
//
// Normative description: ADR-001, section "Runner protocol".
package runnerproto
