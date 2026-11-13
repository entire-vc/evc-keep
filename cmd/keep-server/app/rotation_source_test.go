package app

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	prot "github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/google/uuid"
)

// keyProvider is a stand-in for a provider of a credential on another system
// (a Mesh agent key). Its keys are fake; what matters is who calls it and when.
type keyProvider struct {
	mu       sync.Mutex
	dual     bool
	value    string // the value Issue hands out
	original string // the key valid before the run
	issued   []string
	revoked  []string
	events   []string
	// afterIssue runs after every Issue (a test changes the world between the
	// issue and the revoke).
	afterIssue func()
}

func (k *keyProvider) Kind() string { return "test-key" }
func (k *keyProvider) Capabilities() prot.Capabilities {
	return prot.Capabilities{DualKey: k.dual}
}
func (k *keyProvider) Issue(context.Context, prot.IssueRequest) (prot.Issued, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	id := uuid.NewString()
	k.issued = append(k.issued, id)
	k.events = append(k.events, "issue")
	if k.afterIssue != nil {
		defer k.afterIssue()
	}
	return prot.Issued{KeyID: id, Value: secret.New([]byte(k.value))}, nil
}
func (k *keyProvider) Check(_ context.Context, id string) (prot.Status, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, r := range k.revoked {
		if r == id {
			return prot.Status{Active: false}, nil
		}
	}
	return prot.Status{Active: true}, nil
}
func (k *keyProvider) Current(context.Context, string) (string, bool, error) {
	return k.original, true, nil
}
func (k *keyProvider) Revoke(_ context.Context, id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.revoked = append(k.revoked, id)
	k.events = append(k.events, "revoke")
	return nil
}
func (k *keyProvider) snapshot() (issued, revoked []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.issued...), append([]string(nil), k.revoked...)
}

func boundTo(k *keyProvider, secretID *uuid.UUID) RotatorSource {
	return func(_ context.Context, _, id uuid.UUID) (prot.RotationProvider, bool, error) {
		if id != *secretID {
			return nil, false, nil
		}
		return k, true, nil
	}
}

// The ordinary request (POST .../rotate) of a secret bound to a key provider
// issues the key at the provider, not a random string, lays out exactly that
// value and revokes the original key only after every carrier confirmed.
func TestRotateE2E_BoundSecretUsesTheKeyProvider(t *testing.T) {
	k := &keyProvider{dual: true, original: uuid.NewString(), value: base64.RawURLEncoding.EncodeToString([]byte("test-agent-key-0123456789abcdefgh"))}
	var id uuid.UUID
	r := newRotFixtureWith(t, 2, boundTo(k, &id))
	id = r.secretID
	r.generated = k.value // the value the run must lay out is the provider's
	var seen []string
	res := r.poll(r.start(&seen), &seen)
	if !res.OK || res.Version != "2" || len(res.Carriers) != 2 {
		t.Fatalf("rotation not done: %+v", res)
	}
	if res.Fingerprint != r.fingerprintOf(k.value) {
		t.Fatal("the laid-out version is not the key the provider issued")
	}
	issued, revoked := k.snapshot()
	if len(issued) != 1 {
		t.Fatalf("the provider must be asked for exactly one key, got %d", len(issued))
	}
	if len(revoked) != 1 || revoked[0] != k.original || revoked[0] == issued[0] {
		t.Fatalf("only the original key is revoked, after success: issued %v revoked %v", issued, revoked)
	}
	if got := r.activeVersions(); len(got) != 1 || got[0] != "2" {
		t.Fatalf("after a clean run only version 2 is active, got %v", got)
	}
	r.checkNoLeak(seen)
}

// A failing carrier keeps the original key and opens an incident: nothing the
// provider holds is ended before every carrier confirmed the new key.
func TestRotateE2E_BoundSecretFailingCarrierKeepsOriginalKey(t *testing.T) {
	k := &keyProvider{dual: true, original: uuid.NewString(), value: base64.RawURLEncoding.EncodeToString([]byte("test-agent-key-zyxwvutsrq9876543"))}
	var id uuid.UUID
	r := newRotFixtureWith(t, 3, boundTo(k, &id))
	id = r.secretID
	r.generated = k.value
	r.failDeploy[r.carriers[2]] = true
	var seen []string
	res := r.poll(r.start(&seen), &seen)
	if res.OK || res.ErrorClass != "deploy_failed" || res.Version != "" {
		t.Fatalf("a failing carrier must activate nothing: %+v", res)
	}
	issued, revoked := k.snapshot()
	if len(issued) != 1 {
		t.Fatalf("the new key must come from the provider, got %d issued", len(issued))
	}
	for _, v := range revoked {
		if v == k.original {
			t.Fatal("the original key was revoked although a carrier failed")
		}
	}
	if got := r.activeVersions(); len(got) != 2 || got[0] != "1" {
		t.Fatalf("the old version must stay active, got %v", got)
	}
	// The incident is written by the run's own goroutine just after the result
	// turns failed: wait for it instead of reading the log at once.
	opened := false
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if strings.Contains(string(r.logbuf.Bytes()), "rotation incident opened") {
			opened = true
			break
		}
	}
	if !opened {
		t.Fatal("no incident was opened for the failed run")
	}
	r.checkNoLeak(seen)
}

// A provider that cannot keep the old key valid is refused: this wiring has no
// way back from it, so nothing is issued and the run fails closed.
func TestRotateE2E_ForwardOnlyProviderIsRefused(t *testing.T) {
	k := &keyProvider{dual: false, value: base64.RawURLEncoding.EncodeToString([]byte("test-agent-key-forwardonly-00000"))}
	var id uuid.UUID
	r := newRotFixtureWith(t, 1, boundTo(k, &id))
	id = r.secretID
	var seen []string
	res := r.poll(r.start(&seen), &seen)
	if res.OK {
		t.Fatalf("a forward-only provider must not rotate: %+v", res)
	}
	if issued, revoked := k.snapshot(); len(issued)+len(revoked) != 0 {
		t.Fatalf("the provider was called: issued %v revoked %v", issued, revoked)
	}
}

// A secret the source does not name keeps the generator, and the provider is
// never called for it.
func TestRotateE2E_UnboundSecretStaysGenerated(t *testing.T) {
	k := &keyProvider{dual: true, original: uuid.NewString(), value: base64.RawURLEncoding.EncodeToString([]byte("test-agent-key-unbound-000000000"))}
	other := uuid.New()
	r := newRotFixtureWith(t, 1, boundTo(k, &other))
	var seen []string
	res := r.poll(r.start(&seen), &seen)
	if !res.OK || res.Fingerprint != r.fingerprintOf(r.generated) {
		t.Fatalf("an unbound secret must rotate as before: %+v", res)
	}
	if issued, revoked := k.snapshot(); len(issued)+len(revoked) != 0 {
		t.Fatalf("the provider was called for an unbound secret")
	}
}

// A source that fails (a bindings file that turned unreadable) must not turn a
// bound secret into a generated one: the run fails closed and nothing is issued.
func TestRotateE2E_SourceErrorFailsClosed(t *testing.T) {
	r := newRotFixtureWith(t, 1, func(context.Context, uuid.UUID, uuid.UUID) (prot.RotationProvider, bool, error) {
		return nil, false, errors.New("bindings unavailable")
	})
	var seen []string
	res := r.poll(r.start(&seen), &seen)
	if res.OK || res.Version != "" {
		t.Fatalf("a failing source must not rotate: %+v", res)
	}
	if got := r.activeVersions(); len(got) != 1 || got[0] != "1" {
		t.Fatalf("the old version must stay the only one, got %v", got)
	}
}

// A binding removed after the key was issued must not let the run end as a
// success with the original key alive: the generator's revoke does nothing and
// its check always says "inactive". The revoke step needs the provider that
// issued the key, and refuses (with an incident) when it is gone.
func TestRotateE2E_BindingRemovedMidRunDoesNotReportSuccess(t *testing.T) {
	k := &keyProvider{dual: true, original: uuid.NewString(), value: base64.RawURLEncoding.EncodeToString([]byte("test-agent-key-midrun-0000000000"))}
	var unbound atomic.Bool
	k.afterIssue = func() { unbound.Store(true) }
	var id uuid.UUID
	r := newRotFixtureWith(t, 1, func(ctx context.Context, org, sec uuid.UUID) (prot.RotationProvider, bool, error) {
		if unbound.Load() {
			return nil, false, nil
		}
		return boundTo(k, &id)(ctx, org, sec)
	})
	id = r.secretID
	r.generated = k.value
	var seen []string
	_ = r.start(&seen)
	// The run stops at revoke_failed (a pending revoke, 409 for the next
	// rotation): it is never reported as done while the original key lives.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var n int
		_ = r.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM rotation_runs WHERE secret_id=$1 AND state='revoking_old' AND error_class='revoke_failed'`, r.secretID).Scan(&n)
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run did not stop at a failed revoke")
		}
		time.Sleep(25 * time.Millisecond)
	}
	var done int
	_ = r.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM rotation_runs WHERE secret_id=$1 AND state='done'`, r.secretID).Scan(&done)
	if done != 0 {
		t.Fatal("the run was reported done with the original key alive")
	}
	if _, revoked := k.snapshot(); len(revoked) != 0 {
		t.Fatalf("nothing may be revoked through another provider: %v", revoked)
	}
	if !strings.Contains(string(r.logbuf.Bytes()), "rotation incident opened") {
		t.Fatal("no incident for the unrevoked original key")
	}
}
