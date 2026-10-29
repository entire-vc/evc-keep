// Package loop is keep-runner's execution loop: poll the server for a signed
// job, verify it, check it against the host policy, fetch and open the value,
// write the target, and report a closed runnerproto.Result.
//
// Order is the contract (docs/runner-delivery.md). Before the value is
// requested the runner has verified the organization signature, its own
// identity, the time window and the replay journal, checked the host policy
// and taken a rate-limit slot. The value is requested once per job and never
// again: a lost response ends the job, a fresh deployment is a new job. The
// value's HMAC is checked before targets.Write. The closed Result goes through
// a local 0600 outbox (started, closed, acknowledged); a network failure
// repeats only the sending of that Result.
package loop
