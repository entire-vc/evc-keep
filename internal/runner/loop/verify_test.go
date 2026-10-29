//go:build unix

package loop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// verifyJob queues a verify job the way the server builds it: the fixed
// non-owner Mode/UID/GID, no consumer.
func (e *env) verifyJob(mod func(*runnerproto.Job)) runnerproto.Job {
	e.t.Helper()
	return e.job(func(j *runnerproto.Job) {
		j.Action = runnerproto.ActionVerify
		j.Target = runnerproto.Target{Kind: runnerproto.TargetEnvFile, Path: e.target, Field: "STRIPE_KEY", Mode: 0o600}
		if mod != nil {
			mod(j)
		}
	})
}

func (e *env) carrierHolds(value string) {
	e.t.Helper()
	if err := os.WriteFile(e.target, []byte("STRIPE_KEY="+value+"\n"), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) fpOf(value string) string {
	e.t.Helper()
	fp, err := fingerprint.Compute(e.key, secret.New([]byte(value)))
	if err != nil {
		e.t.Fatal(err)
	}
	return fp
}

func TestVerifyMatchReportsOnlyFingerprintAndWritesNothing(t *testing.T) {
	e := newEnv(t)
	e.carrierHolds(e.value)
	before, _ := os.ReadFile(e.target)
	j := e.verifyJob(nil)
	e.once()
	r := e.f.results[j.JobID]
	if !r.OK || r.Fingerprint != j.ExpectedFingerprint || r.Version != "7" || r.ErrorClass != "" || r.Healthcheck != nil {
		t.Fatalf("match result: %+v", r)
	}
	if after, _ := os.ReadFile(e.target); !bytes.Equal(before, after) {
		t.Fatal("verify changed the carrier")
	}
	if e.f.fetches != 1 || len(e.outboxFiles()) != 0 {
		t.Fatalf("fetches=%d outbox=%v", e.f.fetches, e.outboxFiles())
	}
}

func TestVerifyMismatchNamesTheObservedFingerprint(t *testing.T) {
	e := newEnv(t)
	other := e.c.Value(2)
	e.carrierHolds(other)
	j := e.verifyJob(nil)
	e.once()
	r := e.f.results[j.JobID]
	if r.OK || r.ErrorClass != runnerproto.ErrClassFingerprintMismatch || r.Fingerprint != e.fpOf(other) || r.Fingerprint == j.ExpectedFingerprint {
		t.Fatalf("mismatch result: %+v", r)
	}
	if r.Validate() != nil {
		t.Fatal("mismatch result is outside the contract")
	}
}

func TestVerifyAbsentCarrierIsAMismatchWithoutFingerprintAndWithoutKey(t *testing.T) {
	e := newEnv(t)
	j := e.verifyJob(nil) // no file
	e.once()
	r := e.f.results[j.JobID]
	if r.OK || r.ErrorClass != runnerproto.ErrClassFingerprintMismatch || r.Fingerprint != "" || e.f.fetches != 0 {
		t.Fatalf("absent file: fetches=%d result=%+v", e.f.fetches, r)
	}
	e2 := newEnv(t)
	if err := os.WriteFile(e2.target, []byte("OTHER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	j2 := e2.verifyJob(nil)
	e2.once()
	if r := e2.f.results[j2.JobID]; r.OK || r.ErrorClass != runnerproto.ErrClassFingerprintMismatch || r.Fingerprint != "" {
		t.Fatalf("absent field: %+v", r)
	}
}

// An agent-owned file is refused before the key is requested: the runner must
// not be an oracle for what an agent could plant. The file sits in a
// root-owned sticky directory so that only the file's owner is an agent.
func TestVerifyAgentOwnedCarrierRefusedBeforeKeyAndRead(t *testing.T) {
	tmp, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(tmp, "keep-verify-agent-*")
	if err != nil {
		t.Fatal("no writable sticky /tmp: the agent-owned carrier test cannot run")
	}
	path := f.Name()
	t.Cleanup(func() { _ = os.Remove(path) })
	_ = f.Close()
	e := newEnv(t)
	e.target = path
	e.policy.Targets = []runnerproto.TargetRule{{Kind: runnerproto.TargetEnvFile, PathPrefixes: []string{tmp}, Fields: []string{"STRIPE_KEY"}}}
	// The runner itself must not be an agent, so a root runner gets a foreign owner.
	agent := int64(os.Geteuid())
	if agent == 0 {
		agent = 4242
	}
	e.policy.AgentUIDs = []int64{agent}
	e.r.Policy = e.policy
	e.carrierHolds(e.value)
	if os.Geteuid() == 0 {
		if err := os.Chown(path, int(agent), -1); err != nil {
			t.Fatal(err)
		}
	}
	j := e.verifyJob(nil)
	e.once()
	r := e.f.results[j.JobID]
	if e.f.fetches != 0 || r.OK || r.ErrorClass != runnerproto.ErrClassPolicyDenied || r.Fingerprint != "" {
		t.Fatalf("agent-owned carrier: fetches=%d result=%+v", e.f.fetches, r)
	}
	// Positive control: the same file with nobody declared an agent is read.
	e.policy.AgentUIDs = []int64{1}
	e.r.Policy = e.policy
	j2 := e.verifyJob(nil)
	e.once()
	if r := e.f.results[j2.JobID]; !r.OK || e.f.fetches != 1 {
		t.Fatalf("control: fetches=%d result=%+v", e.f.fetches, r)
	}
}

// A carrier an agent can write is refused as well as one it owns: whatever the
// agent can plant, verify must not tell it whether the guess was right.
func TestVerifyAgentWritableCarrierRefusedBeforeKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		gid  bool
	}{{"world-writable", 0o666, false}, {"agent-group-writable", 0o660, true}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.carrierHolds(e.value)
			// The parent must not be reachable by the agent group, whatever umask made it.
			if err := os.Chmod(e.dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the search bit
				t.Fatal(err)
			}
			if err := os.Chmod(e.target, tc.mode); err != nil {
				t.Fatal(err)
			}
			if tc.gid {
				e.policy.AgentGIDs = []int64{int64(os.Getegid())}
				e.r.Policy = e.policy
			}
			j := e.verifyJob(nil)
			e.once()
			r := e.f.results[j.JobID]
			if e.f.fetches != 0 || r.OK || r.ErrorClass != runnerproto.ErrClassPolicyDenied || r.Fingerprint != "" {
				t.Fatalf("writable carrier: fetches=%d result=%+v", e.f.fetches, r)
			}
			if err := os.Chmod(e.target, 0o600); err != nil {
				t.Fatal(err)
			}
			j2 := e.verifyJob(nil)
			e.once()
			if r := e.f.results[j2.JobID]; !r.OK || e.f.fetches != 1 {
				t.Fatalf("control (0600): fetches=%d result=%+v", e.f.fetches, r)
			}
		})
	}
}

func TestVerifySymlinkCarrierRefusedBeforeKey(t *testing.T) {
	e := newEnv(t)
	real := filepath.Join(e.dir, "real.env")
	if err := os.WriteFile(real, []byte("STRIPE_KEY="+e.value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, e.target); err != nil {
		t.Fatal(err)
	}
	j := e.verifyJob(nil)
	e.once()
	r := e.f.results[j.JobID]
	if e.f.fetches != 0 || r.OK || r.ErrorClass != runnerproto.ErrClassPolicyDenied || r.Fingerprint != "" {
		t.Fatalf("symlink carrier: fetches=%d result=%+v", e.f.fetches, r)
	}
}

func TestVerifyOutsidePolicyRefusedBeforeKey(t *testing.T) {
	e := newEnv(t)
	j := e.verifyJob(func(j *runnerproto.Job) { j.Target.Path = filepath.Join(filepath.Dir(e.dir), "elsewhere.env") })
	e.once()
	if r := e.f.results[j.JobID]; e.f.fetches != 0 || r.OK || r.ErrorClass != runnerproto.ErrClassPolicyDenied {
		t.Fatalf("outside policy: fetches=%d result=%+v", e.f.fetches, r)
	}
}

// forgedKey answers a verify job's key request with whatever the test puts in.
type forgedKey struct {
	*fake
	make func(j runnerproto.Job) runnerproto.ValueEnvelope
}

func (f *forgedKey) FetchValue(_ context.Context, id string) (runnerproto.ValueEnvelope, error) {
	f.fetches++
	return f.make(lastJob[id]), nil
}

// Whatever the server (or a man in the middle) sends, a verify job opens only
// a key sealed for this very job: a value in the envelope, a deploy-style key
// envelope and the envelope of another job are all refused.
func TestVerifyKeyEnvelopeIsJobBoundAndCarriesNoValue(t *testing.T) {
	cases := map[string]func(e *env) func(j runnerproto.Job) runnerproto.ValueEnvelope{
		"value in envelope": func(e *env) func(runnerproto.Job) runnerproto.ValueEnvelope {
			return func(j runnerproto.Job) runnerproto.ValueEnvelope {
				k, _ := fingerprint.NewKey("store1", rawKey(e.key))
				env, err := builtin.SealRunnerKey(j, e.f.recipient, k)
				if err != nil {
					t.Fatal(err)
				}
				env.Sealed = sealTest(t, e.f.recipient, runnerproto.Info(j), []byte(e.value))
				return env
			}
		},
		"deploy-style key info": func(e *env) func(runnerproto.Job) runnerproto.ValueEnvelope {
			return func(j runnerproto.Job) runnerproto.ValueEnvelope {
				return runnerproto.ValueEnvelope{JobID: j.JobID, SealedFingerprintKey: sealTest(t, e.f.recipient, runnerproto.FingerprintKeyInfo(j), rawKey(e.key))}
			}
		},
		"another job's envelope": func(e *env) func(runnerproto.Job) runnerproto.ValueEnvelope {
			return func(j runnerproto.Job) runnerproto.ValueEnvelope {
				o := j
				o.JobID = newID(t)
				o.Nonce = bytes.Repeat([]byte{9}, runnerproto.NonceSize)
				return runnerproto.ValueEnvelope{JobID: j.JobID, SealedFingerprintKey: sealTest(t, e.f.recipient, runnerproto.VerifyKeyInfo(o), rawKey(e.key))}
			}
		},
		"same job, other expiry": func(e *env) func(runnerproto.Job) runnerproto.ValueEnvelope {
			return func(j runnerproto.Job) runnerproto.ValueEnvelope {
				o := j
				o.NotAfter = o.NotAfter.Add(1e9)
				return runnerproto.ValueEnvelope{JobID: j.JobID, SealedFingerprintKey: sealTest(t, e.f.recipient, runnerproto.VerifyKeyInfo(o), rawKey(e.key))}
			}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.carrierHolds(e.value)
			e.r.Transport = &forgedKey{fake: e.f, make: mk(e)}
			j := e.verifyJob(nil)
			e.once()
			r := e.f.results[j.JobID]
			if r.OK || r.ErrorClass != runnerproto.ErrClassValueUnavailable || r.Fingerprint != "" {
				t.Fatalf("result: %+v", r)
			}
		})
	}
}

// Leak test: the value in the carrier, the value the job expected, the
// fingerprint key and the delivery key reach no outward surface on any verify
// outcome. Only the closed Result (fingerprint, version, class) leaves.
func TestVerifyLeaksNothingOnAnyOutcome(t *testing.T) {
	e := newEnv(t)
	e.f.sendErrs = []error{ErrTransport, ErrTransport, ErrTransport, ErrTransport} // keep closed entries on disk
	planted := e.c.Value(3)
	e.carrierHolds(planted)
	e.verifyJob(nil) // mismatch
	e.once()
	e.carrierHolds(e.value)
	e.verifyJob(nil) // match
	e.once()
	_ = os.Remove(e.target)
	e.verifyJob(nil) // absent
	e.once()
	e.verifyJob(func(j *runnerproto.Job) { j.Target.Path = filepath.Join(filepath.Dir(e.dir), "elsewhere.env") }) // policy
	e.once()
	var surfaces []string
	surfaces = append(surfaces, e.logbuf.String())
	for _, n := range e.outboxFiles() {
		b, _ := os.ReadFile(filepath.Join(e.dir, "outbox", n)) //nolint:gosec // G304: test-owned temp dir
		surfaces = append(surfaces, string(b))
	}
	for _, r := range e.f.results {
		b, _ := json.Marshal(r)
		surfaces = append(surfaces, string(b))
	}
	if len(e.outboxFiles()) != 4 {
		t.Fatalf("test setup: %d closed entries on disk, want 4", len(e.outboxFiles()))
	}
	forms := func(b []byte) []string {
		return []string{string(b), hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), fmt.Sprintf("%v", b)}
	}
	for name, raw := range map[string][]byte{"fingerprint key": rawKey(e.key), "delivery key": e.r.Delivery.Bytes()} {
		for _, form := range forms(raw) {
			for _, s := range surfaces {
				if strings.Contains(s, form) {
					t.Fatalf("%s reached an outward surface", name)
				}
			}
		}
	}
	for name, probe := range map[string]canary.Canary{"carrier value": canary.Of(planted), "expected value": canary.Of(e.value)} {
		for _, s := range surfaces {
			if probe.In(s) {
				t.Fatalf("%s reached an outward surface", name)
			}
		}
	}
	// Positive control: the detector sees the value where it does live.
	e.carrierHolds(planted)
	if got, _ := os.ReadFile(e.target); !canary.Of(planted).In(string(got)) {
		t.Fatal("leak detector does not see the value in the carrier file")
	}
	// The run did produce answers worth checking (not four empty surfaces).
	if len(e.f.results) != 0 && len(surfaces) < 5 {
		t.Fatal("test setup: surfaces missing")
	}
}
