package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// pausedJournal takes every record after a pause and keeps the order it saw.
type pausedJournal struct {
	mu   sync.Mutex
	took []audit.Action
	wait time.Duration
}

func (s *pausedJournal) Append(_ context.Context, r audit.Record) (audit.Record, error) {
	time.Sleep(s.wait)
	s.mu.Lock()
	s.took = append(s.took, r.Action)
	s.mu.Unlock()
	return r, nil
}

func (s *pausedJournal) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.took)
}

// cannedJournal always fails, with an error text that carries a probe: the
// drain must not echo what the journal says.
type cannedJournal struct{ text string }

func (c cannedJournal) Append(context.Context, audit.Record) (audit.Record, error) {
	return audit.Record{}, errors.New(c.text)
}

func keyEvents(n int) []builtin.KeyEvent {
	out := make([]builtin.KeyEvent, n)
	for i := range out {
		out[i] = builtin.KeyEvent{Action: "key_level_changed", Org: "o", Actor: "a", From: "user", To: "project"}
	}
	return out
}

// A stop right after a completed change must not lose the outcome: Drain
// returns only once every accepted outcome is in the journal.
func TestKeyLevelAuditorDrainWritesQueuedOutcomes(t *testing.T) {
	j := &pausedJournal{wait: 40 * time.Millisecond}
	var logs bytes.Buffer
	a := newKeyLevelAuditor(j, obs.New(&logs), nil)
	for _, e := range keyEvents(5) {
		a.record(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := j.count(); got != 5 {
		t.Fatalf("journaled %d of 5 outcomes at the end of Drain", got)
	}
}

// Draining an idle queue is immediate and repeatable.
func TestKeyLevelAuditorDrainEmptyAndTwice(t *testing.T) {
	a := newKeyLevelAuditor(&pausedJournal{}, obs.New(&bytes.Buffer{}), nil)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := a.Drain(ctx)
		cancel()
		if err != nil {
			t.Fatalf("drain %d: %v", i, err)
		}
	}
}

// Red input: with the journal down the drain gives up at its deadline, says
// how many outcomes were left, and neither the error nor the log carries what
// the journal answered.
func TestKeyLevelAuditorDrainDeadlineLeaksNothing(t *testing.T) {
	c := canary.Of("kcprobe0drain0leak")
	var logs bytes.Buffer
	a := newKeyLevelAuditor(cannedJournal{text: "journal down " + c.Value(1)}, obs.New(&logs), nil)
	a.backoff = time.Millisecond
	for _, e := range keyEvents(3) {
		a.record(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := a.Drain(ctx)
	if err == nil {
		t.Fatal("drain with a dead journal reported success")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("drain ignored its deadline: %v", time.Since(start))
	}
	if !strings.Contains(err.Error(), "3") {
		t.Fatalf("error does not count what is left: %v", err)
	}
	if !strings.Contains(logs.String(), "audit_undelivered") || !strings.Contains(logs.String(), `"count":3`) {
		t.Fatalf("undelivered outcomes not logged with their count: %s", logs.String())
	}
	surface := err.Error() + logs.String()
	if !c.In(surface + c.Value(1)) {
		t.Fatal("canary scan is blind")
	}
	if c.In(surface) {
		t.Fatal("journal text reached the drain error or the log")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// A graceful stop of a listener is a clean exit, not a serve failure.
func TestServeBothShutdownIsCleanExit(t *testing.T) {
	logger := obs.New(&bytes.Buffer{})
	srv := newHTTPServer(freeAddr(t), http.NotFoundHandler(), logger)
	tlsSrv := newHTTPServer(freeAddr(t), http.NotFoundHandler(), logger)
	tlsSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	done := make(chan int, 1)
	go func() { done <- serveBoth(srv, tlsSrv, logger) }()
	time.Sleep(200 * time.Millisecond)
	_ = srv.Shutdown(context.Background())
	_ = tlsSrv.Shutdown(context.Background())
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code after graceful shutdown = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveBoth did not return after shutdown")
	}
}

// TestKeyLevelAuditorRecordConcurrentWithDrain: a handler that outlives the
// listener shutdown may still report an outcome while Drain runs. It must be
// journaled or refused, never panic on a closed channel or race.
func TestKeyLevelAuditorRecordConcurrentWithDrain(t *testing.T) {
	for i := 0; i < 30; i++ {
		j := &pausedJournal{}
		var logs bytes.Buffer
		a := newKeyLevelAuditor(j, obs.New(&logs), nil)
		var wg sync.WaitGroup
		started := make(chan struct{})
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				started <- struct{}{}
				for _, e := range keyEvents(500) {
					a.record(e)
				}
			}()
		}
		for g := 0; g < 8; g++ {
			<-started
		}
		if err := a.Drain(context.Background()); err != nil {
			t.Fatalf("drain: %v", err)
		}
		wg.Wait()
		// Every outcome is either journaled or refused with a logged class.
		if got := j.count() + strings.Count(logs.String(), "audit_stopped"); got != 8*500 {
			t.Fatalf("outcomes journaled or refused = %d, want %d", got, 8*500)
		}
	}
}

// TestKeyLevelAuditorDrainDeadlineAccountsEveryOutcome: the journal refuses
// throughout and Drain has a short deadline; every produced outcome is then
// journaled, refused after stop, or counted as undelivered.
func TestKeyLevelAuditorDrainDeadlineAccountsEveryOutcome(t *testing.T) {
	const n = 40
	var logs bytes.Buffer
	a := newKeyLevelAuditor(cannedJournal{text: "journal down"}, obs.New(&logs), nil)
	a.backoff = time.Millisecond
	for _, e := range keyEvents(n) {
		a.record(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := a.Drain(ctx)
	if err == nil {
		t.Fatal("drain with a dead journal reported success")
	}
	a.record(keyEvents(1)[0]) // a late handler: refused, not queued
	var undelivered int
	if _, scanErr := fmt.Sscanf(err.Error(), "key level outcomes not journaled at stop: %d left", &undelivered); scanErr != nil {
		t.Fatalf("error carries no count: %v", err)
	}
	refused := strings.Count(logs.String(), "audit_stopped")
	if got := refused + undelivered; got != n+1 {
		t.Fatalf("journaled 0 + refused %d + undelivered %d != produced %d", refused, undelivered, n+1)
	}
	if !strings.Contains(logs.String(), fmt.Sprintf(`"count":%d`, undelivered)) {
		t.Fatalf("log does not carry the undelivered count %d: %s", undelivered, logs.String())
	}
}
