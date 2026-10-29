package runnerproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

var t0 = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

const testFP = "kfp1:s1:abcdefghijklmnop"

func newJobID(t testing.TB) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func deployJob(t testing.TB) Job {
	return Job{
		JobID:               newJobID(t),
		OrgID:               "acme",
		RunnerID:            "runner-1",
		Secret:              SecretRef{StoreID: "store-1", Provider: ProviderBuiltin, Name: "stripe/api-key", Scope: "prod"},
		ExpectedVersion:     "7",
		ExpectedFingerprint: testFP,
		Action:              ActionDeploy,
		Target: Target{
			Kind: TargetEnvFile, Path: "/etc/keep/app/app.env", Field: "STRIPE_KEY",
			Unit: "app.service", Mode: 0o640, UID: 1001, GID: 1001,
		},
		IssuedAt: t0,
		NotAfter: t0.Add(5 * time.Minute),
		Nonce:    bytes.Repeat([]byte{7}, NonceSize),
	}
}

func execJob(t testing.TB) Job {
	j := deployJob(t)
	j.Action, j.Target = ActionExec, Target{}
	j.Exec = &Exec{TemplateID: "migrate", Digest: strings.Repeat("ab", 32), Params: map[string]string{"db": "main", "step": "3"}}
	return j
}

type keys struct {
	signer Signer
	trust  TrustedKeys
}

func newKeys(t testing.TB) keys {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys{Signer{KeyID: "srv-1", Key: priv}, TrustedKeys{"srv-1": pub}}
}

var me = Identity{OrgID: "acme", RunnerID: "runner-1"}

func TestRoundTrip(t *testing.T) {
	k := newKeys(t)
	for _, j := range []Job{deployJob(t), execJob(t)} {
		sj, err := k.signer.Sign(j)
		if err != nil {
			t.Fatal(err)
		}
		got, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), NewMemJournal())
		if err != nil {
			t.Fatalf("%s: %v", j.Action, err)
		}
		if !reflect.DeepEqual(got, j) {
			t.Fatalf("%s: round trip changed the job:\n got %+v\nwant %+v", j.Action, got, j)
		}
	}
}

// Guard: tampering with any signed field is refused. Every field of the job
// is mutated in turn by reflection, so a field added later without being
// covered by the encoding makes this test fail (the mutation would pass).
func TestTamperAnyFieldRejected(t *testing.T) {
	k := newKeys(t)
	for _, base := range []Job{deployJob(t), execJob(t)} {
		sj, err := k.signer.Sign(base)
		if err != nil {
			t.Fatal(err)
		}
		mutations := 0
		for _, m := range mutateEveryField(base) {
			mutations++
			if reflect.DeepEqual(m.job, base) {
				t.Fatalf("%s: mutation %s did not change the job", base.Action, m.name)
			}
			// Attack 1: the attacker re-encodes the tampered job and keeps
			// the old signature.
			// A field the encoding leaves out is acceptable only if setting
			// it makes the job invalid (a target on an exec job).
			p := encodeJob(m.job)
			if bytes.Equal(p, sj.Payload) {
				if m.job.Validate() == nil {
					t.Errorf("%s: field %s is not covered by the canonical encoding", base.Action, m.name)
				}
				continue
			}
			forged := SignedJob{KeyID: sj.KeyID, Payload: p, Sig: sj.Sig}
			if _, err := VerifyJob(forged, k.trust, me, t0.Add(time.Minute), NewMemJournal()); !errors.Is(err, ErrSignature) {
				t.Errorf("%s: tampered %s: got %v, want ErrSignature", base.Action, m.name, err)
			}
		}
		if mutations < 15 {
			t.Fatalf("only %d mutations generated; the walker is broken", mutations)
		}
	}
	// Attack 2: flip every byte of the payload and of the signature.
	sj, _ := k.signer.Sign(deployJob(t))
	for i := range sj.Payload {
		c := sj
		c.Payload = bytes.Clone(sj.Payload)
		c.Payload[i] ^= 1
		if _, err := VerifyJob(c, k.trust, me, t0.Add(time.Minute), NewMemJournal()); err == nil {
			t.Fatalf("payload byte %d flipped and accepted", i)
		}
	}
	for i := range sj.Sig {
		c := sj
		c.Sig = bytes.Clone(sj.Sig)
		c.Sig[i] ^= 1
		if _, err := VerifyJob(c, k.trust, me, t0.Add(time.Minute), NewMemJournal()); !errors.Is(err, ErrSignature) {
			t.Fatalf("sig byte %d flipped: %v", i, err)
		}
	}
	// Attack 3: a valid signature by a key the runner does not trust.
	other := newKeys(t)
	other.signer.KeyID = "srv-1"
	forged, _ := other.signer.Sign(deployJob(t))
	if _, err := VerifyJob(forged, k.trust, me, t0.Add(time.Minute), NewMemJournal()); !errors.Is(err, ErrSignature) {
		t.Fatalf("job signed by an untrusted key: %v", err)
	}
}

type mutation struct {
	name string
	job  Job
}

// mutateEveryField returns one copy of j per leaf field, each with only that
// field changed.
func mutateEveryField(j Job) []mutation {
	var out []mutation
	type getter func(reflect.Value) reflect.Value
	var walk func(path string, get getter)
	walk = func(path string, get getter) {
		v := get(reflect.ValueOf(&j).Elem())
		if v.Kind() == reflect.Pointer {
			if !v.IsNil() {
				walk(path, func(r reflect.Value) reflect.Value { return get(r).Elem() })
			}
			return
		}
		if v.Kind() == reflect.Struct && v.Type() != reflect.TypeOf(time.Time{}) {
			for i := 0; i < v.NumField(); i++ {
				walk(path+"."+v.Type().Field(i).Name, func(r reflect.Value) reflect.Value { return get(r).Field(i) })
			}
			return
		}
		c := cloneJob(j)
		f := get(reflect.ValueOf(&c).Elem())
		switch f.Kind() {
		case reflect.Struct: // time.Time
			f.Set(reflect.ValueOf(f.Interface().(time.Time).Add(-time.Second)))
		case reflect.String:
			f.SetString(f.String() + "x")
		case reflect.Uint32:
			f.SetUint(f.Uint() ^ 0o100)
		case reflect.Int64:
			f.SetInt(f.Int() + 1)
		case reflect.Slice:
			b := bytes.Clone(f.Bytes())
			b[0] ^= 1
			f.SetBytes(b)
		case reflect.Map:
			m := map[string]string{}
			for k, v := range f.Interface().(map[string]string) {
				m[k] = v + "x"
			}
			f.Set(reflect.ValueOf(m))
		default:
			panic("unhandled kind " + f.Kind().String() + " at " + path)
		}
		out = append(out, mutation{path, c})
	}
	walk("Job", func(r reflect.Value) reflect.Value { return r })
	return out
}

// cloneJob deep-copies j so a mutation cannot reach the base.
func cloneJob(j Job) Job {
	c := j
	c.Nonce = bytes.Clone(j.Nonce)
	if j.Exec != nil {
		e := *j.Exec
		e.Params = map[string]string{}
		for k, v := range j.Exec.Params {
			e.Params[k] = v
		}
		c.Exec = &e
	}
	return c
}

func TestReplayRejected(t *testing.T) {
	k := newKeys(t)
	sj, _ := k.signer.Sign(deployJob(t))
	jr := NewMemJournal()
	if _, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), jr); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJob(sj, k.trust, me, t0.Add(2*time.Minute), jr); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: got %v", err)
	}
}

// TestReplayConcurrent: many claimers of one id, exactly one wins.
//
// A test that only lets goroutines race proves what the scheduler happened to
// do: on one core, or on a loaded CI runner, a Claim that dropped its lock
// would still run start to finish before the next claimer got a turn, and the
// test would stay green. So the overlap is forced instead of hoped for:
//
//   - the runtime is given several Ps whatever the runner offers, so that a
//     claimer let in by a dropped lock runs beside the first instead of
//     waiting for its turn on the only P;
//   - every claimer is parked on the journal's own mutex, held by the test,
//     before the test releases it, so the moment the first claimer is inside
//     the others are runnable and need nothing but the lock;
//   - the journal holds a few thousand entries that are already expired, so
//     the first claim sweeps them and its critical section lasts long enough
//     (milliseconds, under -race tens of them) for the others to be let in,
//     even when the runtime has to preempt the first claimer to do it.
//
// With the mutex intact none of this changes the outcome; with it dropped the
// claimers run the sweep and the check-then-write side by side.
func TestReplayConcurrent(t *testing.T) {
	const (
		claimers = 64
		rounds   = 20
		expired  = 5000
	)
	if prev := runtime.GOMAXPROCS(0); prev < 4 {
		runtime.GOMAXPROCS(4)
		defer runtime.GOMAXPROCS(prev)
	}
	// Keys of entries that are expired at t0: past notAfter+ClockSkew.
	stale := make([]string, expired)
	for i := range stale {
		stale[i] = fmt.Sprintf("stale-%d", i)
	}
	staleUntil := t0.Add(-ClockSkew - time.Hour)

	path := filepath.Join(t.TempDir(), "journal")
	fj, err := OpenFileJournal(path, t0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fj.Close() }()
	mj := NewMemJournal()

	for _, c := range []struct {
		name string
		jr   Journal
		mu   *sync.Mutex // the lock Claim takes first
		mem  *MemJournal // where the sweep runs
	}{
		{"mem", mj, &mj.mu, mj},
		{"file", fj, &fj.mu, fj.mem},
	} {
		for round := 0; round < rounds; round++ {
			id := newJobID(t)
			var ok, replay atomic.Int32
			var ready, done sync.WaitGroup

			c.mu.Lock() // the claimers queue up behind this
			for _, k := range stale {
				c.mem.seen[k] = staleUntil
			}
			for i := 0; i < claimers; i++ {
				ready.Add(1)
				done.Add(1)
				go func() {
					defer done.Done()
					ready.Done()
					switch err := c.jr.Claim(id, t0.Add(time.Minute), t0); {
					case err == nil:
						ok.Add(1)
					case errors.Is(err, ErrReplay):
						replay.Add(1)
					}
				}()
			}
			ready.Wait()
			time.Sleep(20 * time.Millisecond) // let them reach the lock
			c.mu.Unlock()
			done.Wait()

			if ok.Load() != 1 || replay.Load() != claimers-1 {
				t.Fatalf("%s round %d: %d claims of one id succeeded and %d were refused as replays, want 1 and %d",
					c.name, round, ok.Load(), replay.Load(), claimers-1)
			}
		}
	}
}

func TestReplaySurvivesRestart(t *testing.T) {
	k := newKeys(t)
	sj, _ := k.signer.Sign(deployJob(t))
	path := filepath.Join(t.TempDir(), "journal")
	jr, err := OpenFileJournal(path, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), jr); err != nil {
		t.Fatal(err)
	}
	_ = jr.Close()
	jr2, err := OpenFileJournal(path, t0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jr2.Close() }()
	if _, err := VerifyJob(sj, k.trust, me, t0.Add(2*time.Minute), jr2); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after restart: got %v", err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode %v", fi.Mode().Perm())
	}
	// A corrupt journal refuses to open instead of forgetting.
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileJournal(path, t0); err == nil {
		t.Fatal("corrupt journal opened")
	}
}

// A crash between Claim's write and its sync can leave a last line without
// its newline. That claim never succeeded, so the journal drops it and
// opens; damage anywhere else still refuses to open.
func TestJournalTornTail(t *testing.T) {
	done, torn := newJobID(t), newJobID(t)
	exp := t0.Add(time.Minute).Unix()
	good := fmt.Sprintf("%s %d\n", done, exp)
	for name, tail := range map[string]string{
		"id and space": torn + " ",
		"id only":      torn,
		"cut number":   fmt.Sprintf("%s %d", torn, exp)[:len(torn)+4],
		"garbage":      "gar",
	} {
		path := filepath.Join(t.TempDir(), "journal")
		if err := os.WriteFile(path, []byte(good+tail), 0o600); err != nil {
			t.Fatal(err)
		}
		jr, err := OpenFileJournal(path, t0)
		if err != nil {
			t.Fatalf("%s: torn last line refused: %v", name, err)
		}
		if err := jr.Claim(done, t0.Add(time.Minute), t0); !errors.Is(err, ErrReplay) {
			t.Fatalf("%s: confirmed id forgotten: got %v", name, err)
		}
		if err := jr.Claim(torn, t0.Add(time.Minute), t0); err != nil {
			t.Fatalf("%s: unconfirmed id: %v", name, err)
		}
		_ = jr.Close()
	}
	for name, body := range map[string]string{
		"bad middle line": good + "garbage\n" + good,
		"bad first line":  torn + "\n" + good,
		"only bad line":   "garbage\n",
	} {
		path := filepath.Join(t.TempDir(), "journal")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileJournal(path, t0); err == nil {
			t.Fatalf("%s: damaged journal opened", name)
		}
	}
}

// Opening rewrites the journal; the new file is synced before it replaces the
// old one and the directory after, and each claim is synced before it
// returns.
func TestJournalDurable(t *testing.T) {
	var synced []string
	defer func(orig func(*os.File) error) { syncFile = orig }(syncFile)
	syncFile = func(f *os.File) error {
		synced = append(synced, f.Name())
		return f.Sync()
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "journal")
	jr, err := OpenFileJournal(path, t0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jr.Close() }()
	if want := []string{path + ".tmp", dir}; !reflect.DeepEqual(synced, want) {
		t.Fatalf("open synced %q, want %q", synced, want)
	}
	synced = nil
	if err := jr.Claim(newJobID(t), t0.Add(time.Minute), t0); err != nil {
		t.Fatal(err)
	}
	if want := []string{path}; !reflect.DeepEqual(synced, want) {
		t.Fatalf("claim synced %q, want %q", synced, want)
	}
}

// After a failed sync the journal's state on disk is unknown: every later
// claim is refused until the runner reopens it.
func TestJournalBrokenAfterFailedSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	jr, err := OpenFileJournal(path, t0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jr.Close() }()
	defer func(orig func(*os.File) error) { syncFile = orig }(syncFile)
	syncFile = func(*os.File) error { return errors.New("disk gone") }
	if err := jr.Claim(newJobID(t), t0.Add(time.Minute), t0); err == nil {
		t.Fatal("claim succeeded without sync")
	}
	syncFile = (*os.File).Sync
	if err := jr.Claim(newJobID(t), t0.Add(time.Minute), t0); !errors.Is(err, ErrJournalBroken) {
		t.Fatalf("claim after failed sync: got %v", err)
	}
}

// A job rejected for another reason must not burn its id.
func TestRejectedJobDoesNotClaim(t *testing.T) {
	k := newKeys(t)
	sj, _ := k.signer.Sign(deployJob(t))
	jr := NewMemJournal()
	if _, err := VerifyJob(sj, k.trust, Identity{OrgID: "acme", RunnerID: "runner-2"}, t0.Add(time.Minute), jr); !errors.Is(err, ErrWrongRunner) {
		t.Fatalf("wrong runner: %v", err)
	}
	if _, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), jr); err != nil {
		t.Fatalf("id was burnt by a rejected job: %v", err)
	}
}

func TestWrongOrgRunnerAndTime(t *testing.T) {
	k := newKeys(t)
	sj, _ := k.signer.Sign(deployJob(t))
	cases := []struct {
		name string
		id   Identity
		now  time.Time
		want error
	}{
		{"other org", Identity{"evil", "runner-1"}, t0.Add(time.Minute), ErrWrongRunner},
		{"other runner", Identity{"acme", "runner-2"}, t0.Add(time.Minute), ErrWrongRunner},
		{"expired", me, t0.Add(5*time.Minute + ClockSkew), ErrExpired},
		{"not yet valid", me, t0.Add(-ClockSkew - time.Second), ErrExpired},
		{"within skew", me, t0.Add(-ClockSkew + time.Second), nil},
	}
	for _, c := range cases {
		_, err := VerifyJob(sj, k.trust, c.id, c.now, NewMemJournal())
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), nil); err == nil {
		t.Fatal("accepted without a journal")
	}
}

func TestInvalidJobs(t *testing.T) {
	bad := map[string]func(*Job){
		"job id v4":           func(j *Job) { j.JobID = "1b4e28ba-2fa1-41d2-883f-0016d3cca427" },
		"bad fingerprint":     func(j *Job) { j.ExpectedFingerprint = "sha256:abc" },
		"lifetime too long":   func(j *Job) { j.NotAfter = j.IssuedAt.Add(MaxJobTTL + time.Second) },
		"not after first":     func(j *Job) { j.NotAfter = j.IssuedAt },
		"short nonce":         func(j *Job) { j.Nonce = j.Nonce[:8] },
		"unknown action":      func(j *Job) { j.Action = "print" },
		"network kind":        func(j *Job) { j.Target.Kind = "http" },
		"url as path":         func(j *Job) { j.Target.Path = "https://evil.example/collect" },
		"relative path":       func(j *Job) { j.Target.Path = "etc/keep/x" },
		"dotdot":              func(j *Job) { j.Target.Path = "/etc/keep/../shadow" },
		"double slash":        func(j *Job) { j.Target.Path = "/etc//keep/x" },
		"nul in path":         func(j *Job) { j.Target.Path = "/etc/keep/x\x00y" },
		"env field injects":   func(j *Job) { j.Target.Field = "A=B\nC" },
		"consumer no prefix":  func(j *Job) { j.Target.Consumer = "app.service" },
		"consumer bad prefix": func(j *Job) { j.Target.Consumer = "cron:app.service" },
		"consumer empty unit": func(j *Job) { j.Target.Consumer = "systemd:" },
		"setuid mode":         func(j *Job) { j.Target.Mode = 0o4750 },
		"zero mode":           func(j *Job) { j.Target.Mode = 0 },
		"negative uid":        func(j *Job) { j.Target.UID = -1 },
		"exec on deploy":      func(j *Job) { j.Exec = &Exec{TemplateID: "x", Digest: strings.Repeat("0", 64)} },
		"file with field":     func(j *Job) { j.Target.Kind = TargetFile },
		"secret name spaces":  func(j *Job) { j.Secret.Name = "a b" },
	}
	for name, f := range bad {
		j := deployJob(t)
		f(&j)
		if err := j.Validate(); !errors.Is(err, ErrInvalidJob) && !errors.Is(err, ErrPolicy) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
		if _, err := newKeys(t).signer.Sign(j); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	e := execJob(t)
	e.Target = deployJob(t).Target
	if e.Validate() == nil {
		t.Error("exec job with a target accepted")
	}
}

// The decoder takes exactly one encoding per job.
func TestNonCanonicalRejected(t *testing.T) {
	j := deployJob(t)
	good := encodeJob(j)
	d := len(jobDomain)
	variants := map[string][]byte{
		"trailing byte": append(bytes.Clone(good), 0),
		"wrong domain":  append([]byte("keep/job/v2\x00"), good[d:]...),
		"swapped order": func() []byte {
			// Move the first field (job id) after the second (org id).
			b := bytes.Clone(good[d:])
			l1 := 2 + int(b[1])
			l2 := 2 + int(b[l1+1])
			out := append([]byte(jobDomain), b[l1:l1+l2]...)
			out = append(out, b[:l1]...)
			return append(out, b[l1+l2:]...)
		}(),
		"duplicate field": func() []byte {
			b := good[d:]
			l1 := 2 + int(b[1])
			out := append([]byte(jobDomain), b[:l1]...)
			return append(out, b...)
		}(),
		"non-minimal length": func() []byte {
			b := good[d:]
			out := append([]byte(jobDomain), b[0], b[1]|0x80, 0)
			return append(out, b[2:]...)
		}(),
		"empty optional": func() []byte {
			c := j
			c.Target.Unit = ""
			e := encodeJob(c)
			i := bytes.Index(e, append([]byte{tagTargetMode, 8}, make([]byte, 0)...))
			out := append(bytes.Clone(e[:i]), tagTargetUnit, 0)
			return append(out, e[i:]...)
		}(),
	}
	for name, b := range variants {
		if _, err := DecodeJob(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := DecodeJob(good); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

// TestNonUTF8NonceRoundTrips guards the binaryTag checklist in canonical.go:
// a field whose wire encoding is not text (nonce, exec params, the
// big-endian integers) must be listed in binaryTag, or DecodeJob runs the
// UTF-8 check on it and a value that happens not to be valid UTF-8 is
// wrongly rejected. deployJob's fixed nonce (16 bytes of 0x07) happens to be
// valid UTF-8 — it, and therefore every other test built on it, would not
// notice tagNonce going missing from binaryTag. This test forces a nonce
// that is genuinely not valid UTF-8 (0xff is never a valid UTF-8 byte, lead
// or continuation), so tagNonce going missing from binaryTag has something
// to catch it. It covers only the nonce: a future binary tag needs its own
// fixture that is guaranteed not to be valid UTF-8, not a reuse of this one.
func TestNonUTF8NonceRoundTrips(t *testing.T) {
	j := deployJob(t)
	j.Nonce = bytes.Repeat([]byte{0xff}, NonceSize)
	k := newKeys(t)
	sj, err := k.signer.Sign(j)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), NewMemJournal())
	if err != nil {
		t.Fatalf("a genuinely non-UTF-8 nonce was rejected — binaryTag no longer covers it: %v", err)
	}
	if !bytes.Equal(got.Nonce, j.Nonce) {
		t.Fatalf("nonce changed in round trip: got %x want %x", got.Nonce, j.Nonce)
	}
}

// legacyEncodeJob reproduces the exact wire format encodeJob produced
// before Target.Consumer existed: tags 1-23, no Consumer field at all. Its
// tag numbers are hardcoded here rather than built from the tagXxx
// constants above: those constants already agree with this layout again
// (the fix moved tagTargetConsumer to the end, after tagNonce), so a
// fixture built from them would pass today and say nothing if a future
// change reshuffles them the same way once more. This copy stays pinned to
// the real historical byte layout regardless of what those constants do.
//
// Deploy/verify jobs only: it never emits the Exec branch (tags 18-20),
// since Target and Exec are mutually exclusive (Validate) and Consumer is a
// Target-only field — an exec job could never have carried one, pre- or
// post-fix, so there is no legacy exec wire format for this helper to pin.
func legacyEncodeJob(j Job) []byte {
	const (
		legacyJobID               byte = 1
		legacyOrgID               byte = 2
		legacyRunnerID            byte = 3
		legacyStoreID             byte = 4
		legacyProvider            byte = 5
		legacySecretName          byte = 6
		legacySecretScope         byte = 7
		legacyExpectedVersion     byte = 8
		legacyExpectedFingerprint byte = 9
		legacyAction              byte = 10
		legacyTargetKind          byte = 11
		legacyTargetPath          byte = 12
		legacyTargetField         byte = 13
		legacyTargetUnit          byte = 14
		legacyTargetMode          byte = 15
		legacyTargetUID           byte = 16
		legacyTargetGID           byte = 17
		legacyIssuedAt            byte = 21
		legacyNotAfter            byte = 22
		legacyNonce               byte = 23
	)
	var e encoder
	e.b.WriteString(jobDomain)
	e.str(legacyJobID, j.JobID)
	e.str(legacyOrgID, j.OrgID)
	e.str(legacyRunnerID, j.RunnerID)
	e.str(legacyStoreID, j.Secret.StoreID)
	e.str(legacyProvider, j.Secret.Provider)
	e.str(legacySecretName, j.Secret.Name)
	e.str(legacySecretScope, j.Secret.Scope)
	e.str(legacyExpectedVersion, j.ExpectedVersion)
	e.str(legacyExpectedFingerprint, j.ExpectedFingerprint)
	e.str(legacyAction, string(j.Action))
	e.str(legacyTargetKind, string(j.Target.Kind))
	e.str(legacyTargetPath, j.Target.Path)
	e.opt(legacyTargetField, j.Target.Field)
	e.opt(legacyTargetUnit, j.Target.Unit)
	e.u64(legacyTargetMode, uint64(j.Target.Mode))
	e.i64(legacyTargetUID, j.Target.UID)
	e.i64(legacyTargetGID, j.Target.GID)
	e.i64(legacyIssuedAt, j.IssuedAt.Unix())
	e.i64(legacyNotAfter, j.NotAfter.Unix())
	e.field(legacyNonce, j.Nonce)
	return e.b.Bytes()
}

// TestDecodeJobAcceptsPreConsumerWireFormat pins a real defect found in
// review: inserting tagTargetConsumer between
// tagTargetUnit and tagTargetMode shifted every tag number after it, so a
// job encoded by the PREVIOUS binary (no Consumer field, tags 1-23) failed
// to decode on the NEW one — "field is not UTF-8", because the old Mode
// field's raw 8-byte binary landed on the new tag number for Consumer,
// which the decoder validates as UTF-8. That is exactly the two-phase-
// rotation window R-DEP-4 exists to survive: a job issued a moment before a
// runner update must still decode after it. The fix moved the new tag to
// the end (see the tag block's doc comment); this test keeps that true by
// decoding a job frozen in the real old byte layout, not one produced by
// today's (already-fixed) encoder.
func TestDecodeJobAcceptsPreConsumerWireFormat(t *testing.T) {
	want := deployJob(t)
	want.Target.Mode, want.Target.UID, want.Target.GID = 0o640, 2002, 3003

	got, err := DecodeJob(legacyEncodeJob(want))
	if err != nil {
		t.Fatalf("legacy (pre-Consumer) wire format rejected: %v", err)
	}
	if got.Target.Consumer != "" {
		t.Fatalf("Consumer = %q, want empty: this format never had that field", got.Target.Consumer)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded job differs from what was encoded:\n got  %+v\nwant %+v", got, want)
	}
}

// TestConsumerRoundTrip guards the two silent-pass mutations left open by
// the fix for TestDecodeJobAcceptsPreConsumerWireFormat's defect: moving the
// encode call for tagTargetConsumer back before tagNonce, or dropping its
// decode case. Neither breaks TestRoundTrip (Target.Consumer is empty on
// every job that test signs) or TestTamperAnyFieldRejected (that test
// mutates fields the encoding already emits, it never adds one). This test
// signs a job whose Consumer is actually set, confirms it round-trips
// through VerifyJob, and walks the decoded payload's own tag stream to
// confirm tagTargetConsumer is genuinely emitted after tagNonce — the last
// tag before tagEnd — not merely present somewhere.
func TestConsumerRoundTrip(t *testing.T) {
	k := newKeys(t)
	j := deployJob(t)
	j.Target.Consumer = "systemd:app.service"

	sj, err := k.signer.Sign(j)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), NewMemJournal())
	if err != nil {
		t.Fatal(err)
	}
	if got.Target.Consumer != j.Target.Consumer {
		t.Fatalf("Consumer = %q, want %q", got.Target.Consumer, j.Target.Consumer)
	}

	d := decoder{b: sj.Payload[len(jobDomain):]}
	var last byte
	for {
		tag, _, err := d.next()
		if err != nil {
			t.Fatalf("walking payload tags: %v", err)
		}
		if tag == tagEnd {
			break
		}
		last = tag
	}
	if last != tagTargetConsumer {
		t.Fatalf("last tag before tagEnd = %d, want tagTargetConsumer (%d): Consumer must stay the last field emitted", last, tagTargetConsumer)
	}
}

// Guard (§4.3): Result has exactly the closed list of fields, recursively.
func TestResultClosedList(t *testing.T) {
	want := map[string][]string{
		"Result":      {"error_class", "fingerprint", "healthcheck", "ok", "version"},
		"Healthcheck": {"checked_at", "duration_ms", "kind", "status"},
	}
	got := map[string][]string{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || rt.PkgPath() != reflect.TypeOf(Result{}).PkgPath() {
			return
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				name = "untagged:" + f.Name
			}
			got[rt.Name()] = append(got[rt.Name()], name)
			walk(f.Type)
		}
		sort.Strings(got[rt.Name()])
	}
	walk(reflect.TypeOf(Result{}))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Result fields changed:\n got %v\nwant %v", got, want)
	}
}

func TestDecodeResult(t *testing.T) {
	ok := `{"ok":true,"fingerprint":"` + testFP + `","version":"7","healthcheck":{"status":"ok","kind":"unit-active","duration_ms":1500,"checked_at":"2026-09-23T12:00:00Z"}}`
	if _, err := DecodeResult([]byte(ok)); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	skipped := `{"ok":true,"healthcheck":{"status":"skipped","kind":"","duration_ms":0,"checked_at":"2026-09-23T12:00:00Z"}}`
	if _, err := DecodeResult([]byte(skipped)); err != nil {
		t.Fatalf("positive control (skipped, no kind): %v", err)
	}
	for name, s := range map[string]string{
		"extra field":                `{"ok":true,"value":"x"}`,
		"case variant key":           `{"OK":true}`,
		"duplicate key":              `{"ok":false,"ok":true}`,
		"nested case key":            `{"ok":true,"healthcheck":{"Status":"ok","kind":"unit-active","duration_ms":1500,"checked_at":"2026-09-23T12:00:00Z"}}`,
		"extra nested field":         `{"ok":true,"healthcheck":{"status":"ok","kind":"unit-active","duration_ms":1500,"checked_at":"2026-09-23T12:00:00Z","stdout":"x"}}`,
		"trailing object":            `{"ok":true} {"value":"x"}`,
		"trailing bracket":           `{"ok":true}]`,
		"trailing brace":             `{"ok":true}}`,
		"trailing garbage":           `{"ok":true} x`,
		"free-form error":            `{"ok":false,"error_class":"leaked sk_live_123"}`,
		"ok with error":              `{"ok":true,"error_class":"internal"}`,
		"failure w/o class":          `{"ok":false}`,
		"bad fingerprint":            `{"ok":true,"fingerprint":"deadbeef"}`,
		"bad health":                 `{"ok":true,"healthcheck":{"status":"whatever"}}`,
		"bad health kind":            `{"ok":true,"healthcheck":{"status":"ok","kind":"shell","duration_ms":1,"checked_at":"2026-09-23T12:00:00Z"}}`,
		"health ok without a kind":   `{"ok":true,"healthcheck":{"status":"ok","kind":"","duration_ms":1,"checked_at":"2026-09-23T12:00:00Z"}}`,
		"health failed without kind": `{"ok":true,"healthcheck":{"status":"failed","kind":"","duration_ms":1,"checked_at":"2026-09-23T12:00:00Z"}}`,
		"health negative duration":   `{"ok":true,"healthcheck":{"status":"ok","kind":"http","duration_ms":-1,"checked_at":"2026-09-23T12:00:00Z"}}`,
	} {
		if _, err := DecodeResult([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Guard: a canary value never appears in a job, a signed job, an envelope
// request or a result, in any of their formatted forms, even though the
// flow that built them held the value.
func TestCanaryNeverInProtocol(t *testing.T) {
	c := canary.New()
	val := c.Value(0)
	v := secret.New([]byte(val))
	key, err := fingerprint.GenerateKey("s1")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := fingerprint.Compute(key, v)
	if err != nil {
		t.Fatal(err)
	}
	j := deployJob(t)
	j.ExpectedFingerprint = fp
	k := newKeys(t)
	sj, err := k.signer.Sign(j)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), NewMemJournal())
	if err != nil {
		t.Fatal(err)
	}
	res := Result{OK: true, Fingerprint: fp, Version: "7", Healthcheck: &Healthcheck{Status: HealthOK, CheckedAt: t0}}
	req := ValueRequest{JobID: j.JobID}

	forms := func(x any) []string {
		b, _ := json.Marshal(x)
		return []string{string(b), fmt.Sprint(x), fmt.Sprintf("%+v", x), fmt.Sprintf("%#v", x)}
	}
	var out []string
	for _, x := range []any{j, got, sj, res, req, Info(j)} {
		out = append(out, forms(x)...)
	}
	out = append(out, string(sj.Payload), string(Info(j)))
	// Positive control: the search finds the value where it is, including
	// inside base64 at an offset ("Basic " + base64("user:" + value)).
	if !c.In(val) || !c.In("Basic "+base64.StdEncoding.EncodeToString([]byte("user:"+val))) {
		t.Fatal("search is broken")
	}
	for _, s := range out {
		if c.In(s) {
			t.Fatal("canary or an encoding leaked into protocol output")
		}
	}
}

// Guard: no protocol type can even hold a value: no secret.Value field, and
// no []byte field except the ones listed.
func TestNoValueCarrier(t *testing.T) {
	allowedBytes := map[string]bool{"Job.Nonce": true, "SignedJob.Payload": true, "SignedJob.Sig": true, "ValueEnvelope.Sealed": true, "ValueEnvelope.SealedFingerprintKey": true}
	sv := reflect.TypeOf(secret.Value{})
	for _, root := range []any{Job{}, SignedJob{}, Result{}, ValueRequest{}, ValueEnvelope{}, HostPolicy{}} {
		var walk func(reflect.Type, string)
		walk = func(rt reflect.Type, path string) {
			for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice && rt.Elem().Kind() != reflect.Uint8 {
				rt = rt.Elem()
			}
			if rt == sv {
				t.Errorf("%s is a secret.Value", path)
			}
			if rt.Kind() == reflect.Slice && !allowedBytes[path] {
				t.Errorf("%s is []byte and could carry a value", path)
			}
			if rt.Kind() != reflect.Struct || rt.PkgPath() != reflect.TypeOf(Job{}).PkgPath() {
				return
			}
			for i := 0; i < rt.NumField(); i++ {
				walk(rt.Field(i).Type, rt.Name()+"."+rt.Field(i).Name)
			}
		}
		walk(reflect.TypeOf(root), reflect.TypeOf(root).Name())
	}
}

func TestInfoBindsJob(t *testing.T) {
	j := deployJob(t)
	base := Info(j)
	for _, f := range []func(*Job){
		func(j *Job) { j.JobID = newJobID(t) },
		func(j *Job) { j.RunnerID = "runner-2" },
		func(j *Job) { j.OrgID = "evil" },
		func(j *Job) { j.Secret.StoreID = "store-2" },
		func(j *Job) { j.Secret.Name = "other" },
		func(j *Job) { j.Secret.Scope = "other-scope" },
		func(j *Job) { j.Secret.Provider = "other-provider" },
		func(j *Job) { j.ExpectedVersion = "8" },
		func(j *Job) { j.ExpectedFingerprint = "kfp1:s1:bbbbbbbbbbbbbbbb" },
	} {
		c := j
		f(&c)
		if bytes.Equal(Info(c), base) {
			t.Fatal("info does not bind a job field")
		}
	}
}

// TestInfoHistoricalWireFormat pins Info's byte output for a fixed job. This
// literal must never change. Scope and provider are appended below as required
// by the protocol ADR before the first production delivery. If a future tag
// lands between two of the tags Info uses (see the APPEND-ONLY note on the tag
// block in canonical.go), every constant after the insertion point renumbers
// and Info produces different
// bytes for the very same job — the server's next seal for that job (or any
// runner still on the previous binary) opens under the wrong info string,
// so HPKE decapsulation fails closed. This test is the only thing that
// would notice before that runner does; TestInfoBindsJob checks that Info
// depends on each field, not that its historical encoding is stable.
func TestInfoHistoricalWireFormat(t *testing.T) {
	j := Job{
		JobID:           "11111111-2222-4333-8444-555555555555",
		OrgID:           "acme",
		RunnerID:        "runner-1",
		Secret:          SecretRef{StoreID: "store-1", Provider: ProviderBuiltin, Name: "stripe/api-key", Scope: "prod"},
		ExpectedVersion: "7",
		// Inlined, not testFP: this literal is pinned forever and must not
		// react to an edit of a fixture shared with other tests.
		ExpectedFingerprint: "kfp1:s1:abcdefghijklmnop",
	}
	const wantHex = "6b6565702f76616c75652f763100012431313131313131312d323232322d343333332d383434342d3535" +
		"35353535353535353535020461636d65030872756e6e65722d31040773746f72652d31060e7374726970652f6170" +
		"692d6b657908013709186b6670313a73313a6162636465666768696a6b6c6d6e6f70"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	// Pin the historical prefix without accepting an arbitrary suffix. The new
	// suffix pins tagSecretScope=7 and tagProvider=5, including their lengths.
	const bindingsHex = "070470726f6405076275696c74696e"
	bindings, err := hex.DecodeString(bindingsHex)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, bindings...)
	if got := Info(j); !bytes.Equal(got, want) {
		t.Fatalf("Info's pinned wire format changed:\n got  %x\nwant  %x\n(a tag constant renumbered — see the APPEND-ONLY note in canonical.go)", got, want)
	}
}

// TestJobHistoricalWireFormat pins encodeJob's byte output for a fixed
// deploy job. Unlike TestRoundTrip (which only checks that today's encoder
// and today's decoder agree with each other, so a mid-list tag insertion
// that renumbers both sides consistently within the same test binary is
// invisible to it), this test catches the renumbering itself: any tag
// inserted anywhere before tagNonce shifts tagIssuedAt/tagNotAfter/tagNonce
// — always present, encoded last — so their tag bytes change here even when
// the insertion point is a target-only or exec-only field this job doesn't
// use. This literal must never change; see the APPEND-ONLY note in
// canonical.go.
func TestJobHistoricalWireFormat(t *testing.T) {
	j := Job{
		JobID:               "11111111-2222-4333-8444-555555555555",
		OrgID:               "acme",
		RunnerID:            "runner-1",
		Secret:              SecretRef{StoreID: "store-1", Provider: ProviderBuiltin, Name: "stripe/api-key", Scope: "prod"},
		ExpectedVersion:     "7",
		ExpectedFingerprint: "kfp1:s1:abcdefghijklmnop",
		Action:              ActionDeploy,
		Target: Target{
			Kind: TargetEnvFile, Path: "/etc/keep/app/app.env", Field: "STRIPE_KEY",
			Unit: "app.service", Mode: 0o640, UID: 1001, GID: 1001,
		},
		// Inlined, not t0: this literal is pinned forever and must not
		// react to an edit of a fixture shared with other tests.
		IssuedAt: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
		NotAfter: time.Date(2026, 9, 23, 12, 5, 0, 0, time.UTC),
		Nonce:    bytes.Repeat([]byte{7}, NonceSize),
	}
	const wantHex = "6b6565702f6a6f622f763100012431313131313131312d323232322d343333332d383434342d353535353535" +
		"353535353535020461636d65030872756e6e65722d31040773746f72652d3105076275696c74696e060e73747269" +
		"70652f6170692d6b6579070470726f6408013709186b6670313a73313a6162636465666768696a6b6c6d6e6f700a0" +
		"66465706c6f790b08656e762d66696c650c152f6574632f6b6565702f6170702f6170702e656e760d0a5354524950" +
		"455f4b45590e0b6170702e736572766963650f0800000000000001a0100800000000000003e9110800000000000003" +
		"e91508000000006ab3bf401608000000006ab3c06c171007070707070707070707070707070707"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := encodeJob(j); !bytes.Equal(got, want) {
		t.Fatalf("Job's historical wire format changed:\n got  %x\nwant %x\n(a tag constant renumbered — see the APPEND-ONLY note in canonical.go)", got, want)
	}
}

// TestExecJobHistoricalWireFormat is TestJobHistoricalWireFormat's
// counterpart for the exec branch: deploy and exec jobs use disjoint field
// sets (Target's Mode/UID/GID vs Exec's TemplateID/Digest/Params), so a tag
// inserted strictly inside the exec-only range (tagExecTemplateID through
// tagExecParams) has nothing in the deploy job's encoding to shift other
// than the always-present trailing fields — this test pins the exec-only
// bytes directly, on top of that.
func TestExecJobHistoricalWireFormat(t *testing.T) {
	j := Job{
		JobID:               "11111111-2222-4333-8444-555555555555",
		OrgID:               "acme",
		RunnerID:            "runner-1",
		Secret:              SecretRef{StoreID: "store-1", Provider: ProviderBuiltin, Name: "stripe/api-key", Scope: "prod"},
		ExpectedVersion:     "7",
		ExpectedFingerprint: "kfp1:s1:abcdefghijklmnop",
		Action:              ActionExec,
		Exec: &Exec{
			TemplateID: "migrate",
			Digest:     strings.Repeat("ab", 32),
			Params:     map[string]string{"db": "main", "step": "3"},
		},
		// Inlined, not t0: this literal is pinned forever and must not
		// react to an edit of a fixture shared with other tests.
		IssuedAt: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
		NotAfter: time.Date(2026, 9, 23, 12, 5, 0, 0, time.UTC),
		Nonce:    bytes.Repeat([]byte{7}, NonceSize),
	}
	const wantHex = "6b6565702f6a6f622f763100012431313131313131312d323232322d343333332d383434342d35353535" +
		"3535353535353535020461636d65030872756e6e65722d31040773746f72652d3105076275696c74696e" +
		"060e7374726970652f6170692d6b6579070470726f6408013709186b6670313a73313a61626364656667" +
		"68696a6b6c6d6e6f700a046578656312076d696772617465134061626162616261626162616261626162" +
		"616261626162616261626162616261626162616261626162616261626162616261626162616261626162" +
		"61626162616214130102646202046d61696e0104737465700201331508000000006ab3bf401608000000" +
		"006ab3c06c171007070707070707070707070707070707"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := encodeJob(j); !bytes.Equal(got, want) {
		t.Fatalf("exec Job's historical wire format changed:\n got  %x\nwant %x\n(a tag constant renumbered — see the APPEND-ONLY note in canonical.go)", got, want)
	}
}

// Guard (threat model 2.3 E): the server releases a value only for a live
// job of this runner, only once, only for builtin deploy/exec.
func TestCheckRelease(t *testing.T) {
	j := deployJob(t)
	now := t0.Add(time.Minute)
	if err := CheckRelease(j, me, now, false); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	verify := j
	verify.Action = ActionVerify
	external := j
	external.Secret.Provider = "onepassword"
	cases := map[string]struct {
		job      Job
		peer     Identity
		now      time.Time
		released bool
		want     error
	}{
		"other runner":   {j, Identity{"acme", "runner-2"}, now, false, ErrWrongRunner},
		"other org":      {j, Identity{"evil", "runner-1"}, now, false, ErrWrongRunner},
		"second release": {j, me, now, true, ErrReleased},
		"expired":        {j, me, j.NotAfter, false, ErrExpired},
		"verify job":     {verify, me, now, false, ErrNotReleasable},
		"not builtin":    {external, me, now, false, ErrNotReleasable},
	}
	for name, c := range cases {
		if err := CheckRelease(c.job, c.peer, c.now, c.released); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

func testPolicy() HostPolicy {
	return HostPolicy{
		Version: 1,
		Targets: []TargetRule{
			{Kind: TargetEnvFile, PathPrefixes: []string{"/etc/keep"}, Fields: []string{"STRIPE_KEY"}, Units: []string{"systemd:app.service", "launchd:com.example.app"}, UnitUIDs: []int64{1001}},
			{Kind: TargetEnvFile, PathPrefixes: []string{"/etc/other"}, Fields: []string{"OTHER_KEY"}},
			{Kind: TargetFile, PathPrefixes: []string{"/etc/keep/files"}},
		},
		AgentUIDs:         []int64{501, 502},
		AgentGIDs:         []int64{20},
		MaxDeploysPerHour: 2,
	}
}

// Guard: the host policy refuses what the server allowed. The job below is
// signed and verified (the server said yes); Check still says no.
func TestHostPolicyOverridesServer(t *testing.T) {
	k := newKeys(t)
	p := testPolicy()
	if err := Check(deployJob(t), p); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	cases := map[string]func(*Job, *HostPolicy){
		"path outside prefix": func(j *Job, _ *HostPolicy) { j.Target.Path = "/home/agent/.env" },
		"prefix lookalike":    func(j *Job, _ *HostPolicy) { j.Target.Path = "/etc/keepevil/app.env" },
		"prefix itself":       func(j *Job, _ *HostPolicy) { j.Target.Path = "/etc/keep" },
		"kind not allowed": func(j *Job, _ *HostPolicy) {
			j.Target.Kind, j.Target.Path = TargetSystemdCredential, "/etc/keep/cred"
			j.Target.Field = ""
		},
		// Threat model 7.1: the field is the agent's choice, the host
		// administrator allows it per rule.
		"field in no rule":           func(j *Job, _ *HostPolicy) { j.Target.Field = "UNLISTED_KEY" },
		"field of another rule only": func(j *Job, _ *HostPolicy) { j.Target.Field = "OTHER_KEY" },
		"echo name the admin allowed": func(j *Job, p *HostPolicy) {
			p.Targets[0].Fields = append(p.Targets[0].Fields, "PYTHONWARNINGS")
			j.Target.Field = "PYTHONWARNINGS"
		},
		"agent owner":            func(j *Job, _ *HostPolicy) { j.Target.UID = 501 },
		"world readable":         func(j *Job, _ *HostPolicy) { j.Target.Mode = 0o644 },
		"agent group readable":   func(j *Job, _ *HostPolicy) { j.Target.GID = 20 },
		"prod on uid_shared":     func(_ *Job, p *HostPolicy) { p.UIDShared = true },
		"exec not allowed":       func(j *Job, _ *HostPolicy) { *j = execJob(t) },
		"empty policy":           func(_ *Job, p *HostPolicy) { p.Targets = nil },
		"invalid policy version": func(_ *Job, p *HostPolicy) { p.Version = 0 },
	}
	for name, f := range cases {
		j, pp := deployJob(t), testPolicy()
		f(&j, &pp)
		if j.Validate() != nil {
			t.Fatalf("%s: job must be valid so that only the policy can refuse it", name)
		}
		sj, err := k.signer.Sign(j)
		if err != nil {
			t.Fatal(err)
		}
		got, err := VerifyJob(sj, k.trust, me, t0.Add(time.Minute), NewMemJournal())
		if err != nil {
			t.Fatalf("%s: server-side job did not verify: %v", name, err)
		}
		if err := Check(got, pp); !errors.Is(err, ErrPolicy) {
			t.Errorf("%s: got %v, want ErrPolicy", name, err)
		}
	}
	// Agent-owned target is refused for verify too (oracle).
	v := deployJob(t)
	v.Action, v.Target.UID = ActionVerify, 502
	if err := Check(v, p); !errors.Is(err, ErrPolicy) {
		t.Errorf("verify of agent-owned target: %v", err)
	}
	// uid_shared allows non-prod, and exec when allowed.
	p2 := testPolicy()
	p2.UIDShared, p2.AllowExec = true, true
	dev := deployJob(t)
	dev.Secret.Scope = "dev"
	if err := Check(dev, p2); err != nil {
		t.Errorf("dev on uid_shared: %v", err)
	}
	ej := execJob(t)
	ej.Secret.Scope = "dev"
	if err := Check(ej, p2); err != nil {
		t.Errorf("exec allowed: %v", err)
	}
}

// Guard (threat model 7.1): a consumer that reads a variable as an option of
// its interpreter echoes the value into its own stderr, which an agent may
// read (PYTHONWARNINGS=<value> -> "Invalid -W option ignored: ... '<value>'").
// Such names are refused even when the host administrator lists them, and a
// rule of a kind with a field must list its fields.
func TestHostPolicyFieldRules(t *testing.T) {
	rule := func(k TargetKind, fields ...string) HostPolicy {
		p := testPolicy()
		p.Targets = []TargetRule{{Kind: k, PathPrefixes: []string{"/etc/keep"}, Fields: fields}}
		return p
	}
	// ruleOpen is a rule whose administrator accepted a name that is not
	// credential-shaped; the echo list must still refuse the known-bad ones.
	ruleOpen := func(k TargetKind, fields ...string) HostPolicy {
		p := rule(k, fields...)
		p.Targets[0].AllowNonCredentialName = true
		return p
	}
	for name, p := range map[string]HostPolicy{
		"env name":          rule(TargetEnvFile, "STRIPE_KEY"),
		"launchd env name":  rule(TargetLaunchdEnv, "STRIPE_KEY"),
		"mcp key":           rule(TargetMCPConfig, "mcpServers.stripe.env.STRIPE_KEY"),
		"hermes key":        rule(TargetHermesConfig, "STRIPE_KEY"),
		"file, no field":    rule(TargetFile),
		"systemd, no field": rule(TargetSystemdCredential),
		"python-ish, but not an option of python": rule(TargetEnvFile, "MY_PYTHON_KEY"),
		"npm token, a value not an option":        rule(TargetEnvFile, "NODE_AUTH_TOKEN"),
		"git token, a value not an option":        rule(TargetEnvFile, "GIT_TOKEN"),
		"github token":                            rule(TargetLaunchdEnv, "GITHUB_TOKEN"),
		"npm token":                               rule(TargetEnvFile, "NPM_TOKEN"),
		"git password, a value not an option":     rule(TargetEnvFile, "GIT_PASSWORD"),
		"google key, not a go setting":            rule(TargetEnvFile, "GOOGLE_API_KEY"),
		"cargo registry token":                    rule(TargetEnvFile, "CARGO_REGISTRY_TOKEN"),
		"php app key":                             rule(TargetEnvFile, "PHP_APP_KEY"),
		"CC as part of a name":                    rule(TargetEnvFile, "CC_API_KEY"),
		"credential exception, lower case":        rule(TargetEnvFile, "node_auth_token"),
		"credential exception, mcp last segment":  rule(TargetMCPConfig, "mcpServers.git.env.GIT_TOKEN"),
		// Round-4 shapes stay narrow: exact make names, whole suffixes.
		"AR as part of a name":              rule(TargetEnvFile, "AR_API_KEY"),
		"LD as part of a name":              rule(TargetEnvFile, "LDAP_PASSWORD"),
		"options word, not a suffix":        rule(TargetEnvFile, "OPTIONS_API_KEY"),
		"args word, not a suffix":           rule(TargetEnvFile, "ARGS_TOKEN"),
		"ends in OPT without an underscore": ruleOpen(TargetEnvFile, "ADOPT"),
		"CCC inside a name":                 rule(TargetEnvFile, "ACCC_TOKEN"),
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("positive control %s: %v", name, err)
		}
	}
	for name, p := range map[string]HostPolicy{
		"env-file rule without fields":     rule(TargetEnvFile),
		"launchd rule without fields":      rule(TargetLaunchdEnv),
		"mcp rule without fields":          rule(TargetMCPConfig),
		"hermes rule without fields":       rule(TargetHermesConfig),
		"file rule with a field":           rule(TargetFile, "STRIPE_KEY"),
		"systemd rule with a field":        rule(TargetSystemdCredential, "STRIPE_KEY"),
		"empty field":                      rule(TargetEnvFile, ""),
		"field with a space":               rule(TargetEnvFile, "A B"),
		"PYTHONWARNINGS":                   rule(TargetEnvFile, "PYTHONWARNINGS"),
		"lower-case pythonwarnings":        rule(TargetEnvFile, "pythonwarnings"),
		"PYTHONSTARTUP":                    rule(TargetEnvFile, "PYTHONSTARTUP"),
		"NODE_OPTIONS":                     rule(TargetLaunchdEnv, "NODE_OPTIONS"),
		"LD_PRELOAD mixed case":            rule(TargetEnvFile, "Ld_Preload"),
		"DYLD_INSERT_LIBRARIES":            rule(TargetLaunchdEnv, "DYLD_INSERT_LIBRARIES"),
		"JAVA_TOOL_OPTIONS":                rule(TargetEnvFile, "JAVA_TOOL_OPTIONS"),
		"_JAVA_OPTIONS":                    rule(TargetEnvFile, "_JAVA_OPTIONS"),
		"JDK_JAVA_OPTIONS":                 rule(TargetEnvFile, "JDK_JAVA_OPTIONS"),
		"PERL5OPT":                         rule(TargetEnvFile, "PERL5OPT"),
		"RUBYOPT":                          rule(TargetEnvFile, "RUBYOPT"),
		"BASH_ENV":                         rule(TargetEnvFile, "BASH_ENV"),
		"ENV":                              rule(TargetEnvFile, "ENV"),
		"PS4":                              rule(TargetEnvFile, "PS4"),
		"PROMPT_COMMAND":                   rule(TargetEnvFile, "PROMPT_COMMAND"),
		"GIT_SSH_COMMAND":                  rule(TargetEnvFile, "GIT_SSH_COMMAND"),
		"GIT_CONFIG_PARAMETERS":            rule(TargetEnvFile, "GIT_CONFIG_PARAMETERS"),
		"GIT_DIR":                          rule(TargetEnvFile, "GIT_DIR"),
		"GIT_WORK_TREE":                    rule(TargetEnvFile, "GIT_WORK_TREE"),
		"GIT_ALTERNATE_OBJECT_DIRECTORIES": rule(TargetEnvFile, "GIT_ALTERNATE_OBJECT_DIRECTORIES"),
		"lower-case git_dir":               rule(TargetLaunchdEnv, "git_dir"),
		"NODE_DEBUG":                       rule(TargetEnvFile, "NODE_DEBUG"),
		"NODE_ICU_DATA":                    rule(TargetEnvFile, "NODE_ICU_DATA"),
		"mcp key ending in GIT_DIR":        rule(TargetMCPConfig, "mcpServers.x.env.GIT_DIR"),
		"credential name as a prefix":      rule(TargetEnvFile, "GIT_TOKEN_HELPER"),
		"DOTNET_STARTUP_HOOKS":             rule(TargetEnvFile, "DOTNET_STARTUP_HOOKS"),
		"ZDOTDIR":                          rule(TargetLaunchdEnv, "ZDOTDIR"),
		"OPENSSL_CONF":                     rule(TargetEnvFile, "OPENSSL_CONF"),
		"CURL_HOME":                        rule(TargetEnvFile, "CURL_HOME"),
		"npm_config_script_shell":          rule(TargetEnvFile, "npm_config_script_shell"),
		"SSH_ASKPASS":                      rule(TargetEnvFile, "SSH_ASKPASS"),
		"https_proxy":                      rule(TargetEnvFile, "https_proxy"),
		"PATH":                             rule(TargetEnvFile, "PATH"),
		"HOME":                             rule(TargetEnvFile, "HOME"),
		"IFS":                              rule(TargetEnvFile, "IFS"),
		"mcp key ending in NODE_OPTIONS":   rule(TargetMCPConfig, "mcpServers.x.env.NODE_OPTIONS"),
		"hermes PYTHONPATH, lower case":    rule(TargetHermesConfig, "pythonpath"),
		"LANG":                             rule(TargetEnvFile, "LANG"),
		"LC_ALL":                           rule(TargetEnvFile, "LC_ALL"),
		"TERM":                             rule(TargetLaunchdEnv, "TERM"),
		"SUDO_ASKPASS":                     rule(TargetEnvFile, "SUDO_ASKPASS"),
		"LESSOPEN":                         rule(TargetEnvFile, "LESSOPEN"),
		"MANPAGER":                         rule(TargetEnvFile, "MANPAGER"),
		"BROWSER":                          rule(TargetEnvFile, "BROWSER"),
		"GCONV_PATH":                       rule(TargetEnvFile, "GCONV_PATH"),
		"HOSTALIASES":                      rule(TargetEnvFile, "HOSTALIASES"),
		"RES_OPTIONS":                      rule(TargetEnvFile, "RES_OPTIONS"),
		"GOFLAGS":                          rule(TargetEnvFile, "GOFLAGS"),
		"GOTOOLCHAIN":                      rule(TargetEnvFile, "GOTOOLCHAIN"),
		"GOPROXY":                          rule(TargetEnvFile, "GOPROXY"),
		"goproxy":                          rule(TargetEnvFile, "goproxy"),
		"CGO_CFLAGS":                       rule(TargetEnvFile, "CGO_CFLAGS"),
		"PHPRC":                            rule(TargetEnvFile, "PHPRC"),
		"PHP_INI_SCAN_DIR":                 rule(TargetEnvFile, "PHP_INI_SCAN_DIR"),
		"R_PROFILE_USER":                   rule(TargetEnvFile, "R_PROFILE_USER"),
		"R_ENVIRON_USER":                   rule(TargetEnvFile, "R_ENVIRON_USER"),
		"LUA_INIT":                         rule(TargetEnvFile, "LUA_INIT"),
		"RUSTC_WRAPPER":                    rule(TargetEnvFile, "RUSTC_WRAPPER"),
		"RUSTFLAGS":                        rule(TargetEnvFile, "RUSTFLAGS"),
		"CARGO_BUILD_RUSTC_WRAPPER":        rule(TargetEnvFile, "CARGO_BUILD_RUSTC_WRAPPER"),
		"MAKEFLAGS":                        rule(TargetEnvFile, "MAKEFLAGS"),
		"CC":                               rule(TargetEnvFile, "CC"),
		"CXX":                              rule(TargetEnvFile, "CXX"),
		"PS1":                              rule(TargetEnvFile, "PS1"),
		"TMPDIR":                           rule(TargetEnvFile, "TMPDIR"),
		"SHELL":                            rule(TargetEnvFile, "SHELL"),
		"XDG_CONFIG_HOME":                  rule(TargetEnvFile, "XDG_CONFIG_HOME"),
		"KUBECONFIG":                       rule(TargetEnvFile, "KUBECONFIG"),
		"DOCKER_HOST":                      rule(TargetEnvFile, "DOCKER_HOST"),
		"SSL_CERT_FILE":                    rule(TargetEnvFile, "SSL_CERT_FILE"),
		"REQUESTS_CA_BUNDLE":               rule(TargetEnvFile, "REQUESTS_CA_BUNDLE"),
		"NODE_EXTRA_CA_CERTS":              rule(TargetEnvFile, "NODE_EXTRA_CA_CERTS"),
		"CURL_CA_BUNDLE":                   rule(TargetEnvFile, "CURL_CA_BUNDLE"),
		"SSLKEYLOGFILE":                    rule(TargetEnvFile, "SSLKEYLOGFILE"),
		"JAVA_HOME":                        rule(TargetEnvFile, "JAVA_HOME"),
		"mcp command, not an env var":      rule(TargetMCPConfig, "mcpServers.x.command"),
		"mcp url, not an env var":          rule(TargetMCPConfig, "mcpServers.x.url"),
		"mcp key outside mcpServers":       rule(TargetMCPConfig, "secrets.x.env.API_KEY"),
		"mcp env var too deep":             rule(TargetMCPConfig, "mcpServers.x.env.A.B"),
		"mcp single segment":               rule(TargetMCPConfig, "API_KEY"),
		// Round-3 leak-review finding: build-tool and runtime-option
		// variables echoed into a compiler invocation or a VM's own
		// printed command line (threat model 7.1, same class as GOFLAGS).
		"CFLAGS":                   rule(TargetEnvFile, "CFLAGS"),
		"LDFLAGS":                  rule(TargetEnvFile, "LDFLAGS"),
		"CPPFLAGS":                 rule(TargetEnvFile, "CPPFLAGS"),
		"MAVEN_OPTS":               rule(TargetEnvFile, "MAVEN_OPTS"),
		"GRADLE_OPTS":              rule(TargetLaunchdEnv, "GRADLE_OPTS"),
		"SBT_OPTS":                 rule(TargetEnvFile, "SBT_OPTS"),
		"COMPLUS_ZapDisable":       rule(TargetEnvFile, "COMPLUS_ZapDisable"),
		"DOTNET_ADDITIONAL_DEPS":   rule(TargetEnvFile, "DOTNET_ADDITIONAL_DEPS"),
		"PIP_INDEX_URL":            rule(TargetEnvFile, "PIP_INDEX_URL"),
		"PIP_CONFIG_FILE":          rule(TargetEnvFile, "PIP_CONFIG_FILE"),
		"UV_INDEX_URL":             rule(TargetEnvFile, "UV_INDEX_URL"),
		"BUNDLE_GEMFILE":           rule(TargetEnvFile, "BUNDLE_GEMFILE"),
		"GEM_HOME":                 rule(TargetEnvFile, "GEM_HOME"),
		"ERL_AFLAGS":               rule(TargetEnvFile, "ERL_AFLAGS"),
		"TZ":                       rule(TargetEnvFile, "TZ"),
		"CLASSPATH":                rule(TargetEnvFile, "CLASSPATH"),
		"GLIBC_TUNABLES":           rule(TargetLaunchdEnv, "GLIBC_TUNABLES"),
		"NLSPATH":                  rule(TargetEnvFile, "NLSPATH"),
		"LOCPATH":                  rule(TargetEnvFile, "LOCPATH"),
		"TERMINFO":                 rule(TargetEnvFile, "TERMINFO"),
		"HISTFILE":                 rule(TargetEnvFile, "HISTFILE"),
		"VIMINIT":                  rule(TargetEnvFile, "VIMINIT"),
		"EXINIT":                   rule(TargetEnvFile, "EXINIT"),
		"lower-case cflags":        rule(TargetEnvFile, "cflags"),
		"mcp key ending in CFLAGS": rule(TargetMCPConfig, "mcpServers.x.env.CFLAGS"),
		// Round-4 leak-review finding: make's implicit-rule variables are
		// spliced into the printed recipe (TARGET_ARCH=<v> make probe.o ->
		// "cc <v> -c -o probe.o probe.c"), clang prints CCC_OVERRIDE_OPTIONS,
		// toolchain and console-tool option variables quote the value back.
		// Closed by shape where one exists (_OPTIONS, _ARGS, _OPT, CCC_).
		"TARGET_ARCH":          rule(TargetEnvFile, "TARGET_ARCH"),
		"LDLIBS":               rule(TargetEnvFile, "LDLIBS"),
		"LOADLIBES":            rule(TargetEnvFile, "LOADLIBES"),
		"AR":                   rule(TargetEnvFile, "AR"),
		"AS":                   rule(TargetEnvFile, "AS"),
		"CPP":                  rule(TargetEnvFile, "CPP"),
		"LD":                   rule(TargetEnvFile, "LD"),
		"FC":                   rule(TargetEnvFile, "FC"),
		"PC":                   rule(TargetEnvFile, "PC"),
		"LEX":                  rule(TargetEnvFile, "LEX"),
		"YACC":                 rule(TargetEnvFile, "YACC"),
		"OUTPUT_OPTION":        rule(TargetEnvFile, "OUTPUT_OPTION"),
		"MAKEFILES":            rule(TargetEnvFile, "MAKEFILES"),
		"CCC_OVERRIDE_OPTIONS": rule(TargetEnvFile, "CCC_OVERRIDE_OPTIONS"),
		"CCC_PRINT_PHASES, only the prefix catches it": rule(TargetEnvFile, "CCC_PRINT_PHASES"),
		"CCC_ADD_ARGS":                           rule(TargetEnvFile, "CCC_ADD_ARGS"),
		"SDKROOT":                                rule(TargetEnvFile, "SDKROOT"),
		"DEVELOPER_DIR":                          rule(TargetEnvFile, "DEVELOPER_DIR"),
		"LIBRARY_PATH":                           rule(TargetEnvFile, "LIBRARY_PATH"),
		"CPATH":                                  rule(TargetEnvFile, "CPATH"),
		"C_INCLUDE_PATH":                         rule(TargetEnvFile, "C_INCLUDE_PATH"),
		"GZIP":                                   rule(TargetEnvFile, "GZIP"),
		"BLOCKSIZE":                              rule(TargetEnvFile, "BLOCKSIZE"),
		"GNUPGHOME":                              rule(TargetEnvFile, "GNUPGHOME"),
		"DOCKER_CONTEXT":                         rule(TargetEnvFile, "DOCKER_CONTEXT"),
		"DOCKER_CONFIG":                          rule(TargetEnvFile, "DOCKER_CONFIG"),
		"TAR_OPTIONS":                            rule(TargetEnvFile, "TAR_OPTIONS"),
		"GREP_OPTIONS":                           rule(TargetEnvFile, "GREP_OPTIONS"),
		"XZ_OPT":                                 rule(TargetEnvFile, "XZ_OPT"),
		"DOCKER_BUILD_ARGS":                      rule(TargetEnvFile, "DOCKER_BUILD_ARGS"),
		"LESS":                                   rule(TargetEnvFile, "LESS"),
		"lower-case target_arch":                 rule(TargetEnvFile, "target_arch"),
		"mcp key ending in CCC_OVERRIDE_OPTIONS": rule(TargetMCPConfig, "mcpServers.x.env.CCC_OVERRIDE_OPTIONS"),
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		// The echo list is the second layer: with the administrator's
		// explicit opt-in to non-credential names it must refuse the same
		// rule on its own.
		open := p
		open.Targets = append([]TargetRule(nil), p.Targets...)
		open.Targets[0].AllowNonCredentialName = true
		if err := open.Validate(); err == nil {
			t.Errorf("%s: accepted with allow_non_credential_name", name)
		}
	}
	// And the job side: an allowed key of another kind passes, the same
	// key under a different last segment does not.
	p := rule(TargetMCPConfig, "mcpServers.stripe.env.STRIPE_KEY")
	j := deployJob(t)
	j.Target.Kind, j.Target.Path, j.Target.Field = TargetMCPConfig, "/etc/keep/mcp.json", "mcpServers.stripe.env.STRIPE_KEY"
	if err := Check(j, p); err != nil {
		t.Errorf("positive control, allowed mcp key: %v", err)
	}
	j.Target.Field = "mcpServers.stripe.env.OTHER_KEY"
	if err := Check(j, p); !errors.Is(err, ErrPolicy) {
		t.Errorf("mcp key outside the rule: got %v, want ErrPolicy", err)
	}
}

// Guard (threat model 7.1, card e1f0d8e5): the echo-name list can never be
// complete, so the first layer is the shape of the name. A rule lists only
// credential-shaped names unless the administrator sets
// allow_non_credential_name on that rule, and a rule that does is reported
// by Warnings.
func TestHostPolicyCredentialShapedFields(t *testing.T) {
	rule := func(open bool, k TargetKind, fields ...string) HostPolicy {
		p := testPolicy()
		p.Targets = []TargetRule{{Kind: k, PathPrefixes: []string{"/etc/keep"}, Fields: fields, AllowNonCredentialName: open}}
		return p
	}
	for _, f := range []string{
		"GITHUB_TOKEN", "NODE_AUTH_TOKEN", "STRIPE_KEY", "STRIPE_API_KEY", "DB_PASSWORD",
		"APP_SECRET", "AWS_CREDENTIAL", "github_token", "GIT_PASSWORD", "CARGO_REGISTRY_TOKEN",
		"S3_2_KEY",
	} {
		p := rule(false, TargetEnvFile, f)
		if err := p.Validate(); err != nil {
			t.Errorf("credential-shaped %q refused: %v", f, err)
		}
		if w := p.Warnings(); len(w) != 0 {
			t.Errorf("credential-shaped %q warned: %v", f, w)
		}
	}
	if err := rule(false, TargetMCPConfig, "mcpServers.x.env.STRIPE_KEY").Validate(); err != nil {
		t.Errorf("mcp key with a credential-shaped last segment: %v", err)
	}
	// Names the review found echoing their value (card e1f0d8e5), plus the
	// unconfirmed ones named there, and plain custom names.
	notCredential := []string{
		"LINT", "MAKE", "MAKE_COMMAND", "OBJCPLUS_INCLUDE_PATH", "RSYNC_RSH",
		"DOCKER_DEFAULT_PLATFORM", "DOCKER_CERT_PATH", "COMPOSE_FILE", "COMPOSE_ENV_FILES",
		"PERL_SIGNALS", "RUBY_GC_HEAP_INIT_SLOTS", "RUBY_GC_HEAP_GROWTH_FACTOR",
		"TF_CLI_ARGS_plan", "AWS_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION", "AWS_CONFIG_FILE",
		"COLUMNS", "TABSIZE", "QUOTING_STYLE", "TIME_STYLE", "CMAKE_PREFIX_PATH", "PKG_CONFIG",
		"CCACHE_PREFIX", "CVS_RSH", "PGHOST", "CUSTOM_NAME", "KEY", "TOKEN", "STRIPE_KEY_PATH",
		"TOKEN_FILE", "SECRET_HELPER", "A-KEY", "STRIPE KEY",
	}
	for _, f := range notCredential {
		err := rule(false, TargetEnvFile, f).Validate()
		if err == nil {
			t.Errorf("non-credential name %q accepted without allow_non_credential_name", f)
			continue
		}
		if strings.Contains(err.Error(), "never written") {
			t.Errorf("refusal for %q promises a guarantee: %v", f, err)
		}
	}
	// Validate refuses a malformed name before the shape is looked at, so
	// the anchors of the shape are checked on the predicate itself (Warnings
	// reaches it without Validate).
	for f, want := range map[string]bool{
		"STRIPE_KEY": true, "mcpServers.x.env.STRIPE_KEY": true,
		"A-B_KEY": false, "MY APP_TOKEN": false, "x.y": false, "": false,
		"a b_key": false, "KEY": false,
	} {
		if got := credentialShaped(f); got != want {
			t.Errorf("credentialShaped(%q) = %v, want %v", f, got, want)
		}
	}
	// With the explicit opt-in a custom name is accepted and reported; the
	// echo list still applies on top.
	for _, f := range []string{"AWS_PROFILE", "CUSTOM_NAME", "mcpServers.x.env.CUSTOM_NAME"} {
		k := TargetEnvFile
		if strings.HasPrefix(f, "mcpServers.") {
			k = TargetMCPConfig
		}
		p := rule(true, k, f)
		if err := p.Validate(); err != nil {
			t.Errorf("opted-in %q refused: %v", f, err)
		}
		w := p.Warnings()
		if len(w) != 1 || !strings.Contains(w[0], f) {
			t.Errorf("opted-in %q: warnings %v", f, w)
		}
	}
	for _, f := range []string{
		"PYTHONWARNINGS", "LD_PRELOAD", "GIT_DIR", "PATH",
		// the names found echoing their value by the review of card e1f0d8e5
		"LINT", "MAKE", "MAKE_COMMAND", "OBJCPLUS_INCLUDE_PATH", "RSYNC_RSH",
		"DOCKER_DEFAULT_PLATFORM", "DOCKER_CERT_PATH", "COMPOSE_FILE", "COMPOSE_ENV_FILES",
		"PERL_SIGNALS", "RUBY_GC_HEAP_INIT_SLOTS", "RUBY_GC_HEAP_GROWTH_FACTOR",
		"TF_CLI_ARGS_plan", "CMAKE_PREFIX_PATH", "PKG_CONFIG", "CCACHE_PREFIX", "CVS_RSH",
		"COLUMNS", "TABSIZE", "QUOTING_STYLE", "TIME_STYLE",
		// credential-shaped, yet read as a path or printed back
		"VAULT_CLIENT_KEY", "CONSUL_CLIENT_KEY", "DOCKER_TLS_KEY", "PG_SSL_KEY", "ETCDCTL_KEY",
		"TF_VAR_db_password", "TF_VAR_API_TOKEN",
	} {
		if err := rule(true, TargetEnvFile, f).Validate(); err == nil {
			t.Errorf("echo name %q accepted with allow_non_credential_name", f)
		}
	}
	// The flag on a rule whose names are all credential-shaped adds nothing
	// to warn about.
	if w := rule(true, TargetEnvFile, "STRIPE_KEY").Warnings(); len(w) != 0 {
		t.Errorf("opted-in credential-shaped rule warned: %v", w)
	}
	// It is read from the policy file, and an unknown key is still refused.
	parse := func(extra string) error {
		_, err := ParseHostPolicy([]byte(`{"version":1,"max_deploys_per_hour":1,"targets":[{"kind":"env-file","path_prefixes":["/etc/keep"],"fields":["CUSTOM_NAME"]` + extra + `}]}`))
		return err
	}
	if err := parse(`,"allow_non_credential_name":true`); err != nil {
		t.Errorf("policy with the opt-in: %v", err)
	}
	if err := parse(``); err == nil {
		t.Error("policy without the opt-in accepted a non-credential name")
	}
	if err := parse(`,"allow_non_credential_names":true`); err == nil {
		t.Error("misspelled opt-in key accepted")
	}
	// A job under an opted-in rule is checked like any other.
	p := rule(true, TargetEnvFile, "CUSTOM_NAME")
	j := deployJob(t)
	j.Target.Path, j.Target.Field = "/etc/keep/app.env", "CUSTOM_NAME"
	if err := Check(j, p); err != nil {
		t.Errorf("job for an opted-in field: %v", err)
	}
}

// Round-3 leak-review finding: CFLAGS is not a theoretical hazard — a real
// `make`/`cc` invocation echoes it into the printed compiler command line,
// the same class as the PYTHONWARNINGS example in this package's doc
// comment. Skips (never fails) where no C toolchain is installed: the
// property under test is echoField's refusal, which the map-driven cases
// above already assert unconditionally; this test is the live-consumer
// corroboration for that one entry, not its only proof.
func TestEchoField_CFLAGS_RealConsumer(t *testing.T) {
	if !echoField("CFLAGS") {
		t.Fatal("CFLAGS must be refused by echoField before this test can prove why")
	}
	for _, tool := range []string{"make", "cc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "probe.c"), []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte("probe.o: probe.c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// TARGET_ARCH is the round-4 finding: the same compile recipe prints it.
	for _, name := range []string{"CFLAGS", "TARGET_ARCH"} {
		if !echoField(name) {
			t.Fatalf("%s must be refused by echoField", name)
		}
		canaryValue := "KEEP-CANARY-" + name + "-PROBE-0001"
		_ = os.Remove(filepath.Join(dir, "probe.o"))
		cmd := exec.Command("make", "probe.o")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), name+"="+canaryValue)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), canaryValue) {
			t.Skipf("this make/cc did not echo %s on its own command line; cannot demonstrate the hazard on this runner", name)
		}
	}
}

// Guard: a verify job must never carry a consumer. Check's ActionVerify
// branch returns nil before it ever reaches the consumer-allowlist gate
// below (verify never restarts anything, so there is nothing there to
// authorize) — without this, a verify job naming a consumer outside any
// rule's allowlist would still pass Check, because the allowlist check it
// would otherwise hit is never reached for that action.
func TestVerifyJobRejectsConsumer(t *testing.T) {
	p := testPolicy()
	v := deployJob(t)
	v.Action = ActionVerify
	if err := v.Validate(); err != nil {
		t.Fatalf("positive control: plain verify job refused: %v", err)
	}
	if err := Check(v, p); err != nil {
		t.Fatalf("positive control: plain verify job refused by Check: %v", err)
	}
	v.Target.Consumer = "systemd:other.service" // not in p's allowlist for this rule
	if err := v.Validate(); !errors.Is(err, ErrInvalidJob) {
		t.Fatalf("verify job with consumer: Validate got %v, want ErrInvalidJob", err)
	}
	if err := Check(v, p); !errors.Is(err, ErrInvalidJob) {
		t.Fatalf("verify job with consumer: Check got %v, want ErrInvalidJob (via Validate, not silently admitted)", err)
	}
}

// Guard: a deploy job's consumer unit must be in the matching target
// rule's allowlist. Deny by default — an empty (or absent) allowlist permits
// no restart for that rule, even though the deploy itself is allowed. A
// signed job cannot widen this: a compromised server must not be able to
// make the runner restart an arbitrary host unit just by naming it in a
// job it signs.
func TestConsumerUnitMustBeAllowlisted(t *testing.T) {
	p := testPolicy()
	j := deployJob(t)
	j.Target.Consumer = "systemd:app.service"
	if err := Check(j, p); err != nil {
		t.Fatalf("positive control: allowlisted consumer refused: %v", err)
	}
	j.Target.Consumer = "systemd:other.service"
	if err := Check(j, p); !errors.Is(err, ErrPolicy) {
		t.Fatalf("consumer outside the allowlist: got %v, want ErrPolicy", err)
	}
	j.Target.Consumer = "systemd:app.service"
	p2 := testPolicy()
	p2.Targets[0].Units = nil
	if err := Check(j, p2); !errors.Is(err, ErrPolicy) {
		t.Fatalf("empty allowlist (deny by default): got %v, want ErrPolicy", err)
	}
	// No consumer named — no restart requested — never checked against the
	// allowlist at all, allowlisted or not.
	j.Target.Consumer = ""
	if err := Check(j, p2); err != nil {
		t.Fatalf("job without a consumer refused: %v", err)
	}
}

// Guard: a launchd restart targets user/<uid>/<label>, and the uid comes
// from the signed job. The allowlist therefore binds the pair (unit, uid):
// a listed label under an unlisted uid is a different launchd domain the
// host never authorised. Deny by default: no UnitUIDs, no launchd restart.
func TestLaunchdConsumerBoundToUID(t *testing.T) {
	p := testPolicy()
	j := deployJob(t)
	j.Target.Consumer = "launchd:com.example.app"
	if err := Check(j, p); err != nil {
		t.Fatalf("positive control: listed (unit, uid) refused: %v", err)
	}
	j.Target.UID = 1002
	if err := Check(j, p); !errors.Is(err, ErrPolicy) {
		t.Fatalf("listed unit under unlisted uid: got %v, want ErrPolicy", err)
	}
	j.Target.UID = 1001
	p2 := testPolicy()
	p2.Targets[0].UnitUIDs = nil
	if err := Check(j, p2); !errors.Is(err, ErrPolicy) {
		t.Fatalf("empty unit_uids (deny by default): got %v, want ErrPolicy", err)
	}
	// systemd has no per-uid domain here: the uid list is ignored, the unit
	// allowlist alone decides.
	j.Target.Consumer = "systemd:app.service"
	if err := Check(j, p2); err != nil {
		t.Fatalf("systemd consumer with empty unit_uids refused: %v", err)
	}
}

// Guard: a policy written before unit_uids existed must parse, and read as
// "no launchd restart", never as a panic or as "any uid".
func TestPolicyWithoutUnitUIDsDeniesLaunchd(t *testing.T) {
	old := []byte(`{"version":1,"max_deploys_per_hour":1,"targets":[{"kind":"env-file","path_prefixes":["/etc/keep"],"fields":["STRIPE_KEY"],"units":["launchd:com.example.app"]}]}`)
	p, err := ParseHostPolicy(old)
	if err != nil {
		t.Fatalf("old policy without unit_uids: %v", err)
	}
	j := deployJob(t)
	j.Target.Consumer = "launchd:com.example.app"
	if err := Check(j, p); !errors.Is(err, ErrPolicy) {
		t.Fatalf("old policy, launchd consumer: got %v, want ErrPolicy", err)
	}
	if got := ResolveHealth(p, j.Target); got != (HealthCheck{}) {
		t.Fatalf("ResolveHealth on a refused pair: %+v", got)
	}
	bad := []byte(`{"version":1,"max_deploys_per_hour":1,"targets":[{"kind":"env-file","path_prefixes":["/etc/keep"],"fields":["STRIPE_KEY"],"units":["launchd:x"],"unit_uids":[-1]}]}`)
	if _, err := ParseHostPolicy(bad); err == nil {
		t.Fatalf("negative unit_uid accepted")
	}
	tmpl := `{"version":1,"max_deploys_per_hour":1,"targets":[{"kind":"env-file","path_prefixes":["/etc/keep"],"fields":["STRIPE_KEY"],"units":["launchd:x"],"unit_uids":[%d]}]}`
	if _, err := ParseHostPolicy([]byte(fmt.Sprintf(tmpl, 1<<31-1))); err != nil {
		t.Fatalf("largest valid unit_uid refused: %v", err)
	}
	if _, err := ParseHostPolicy([]byte(fmt.Sprintf(tmpl, 1<<31))); err == nil {
		t.Fatalf("unit_uid above the uid range accepted")
	}
}

// Guard: a healthcheck's parameters are validated in isolation, and
// the closed kind list, loopback-only http host and required body marker
// are all enforced here — the one place a bad definition can be rejected
// before any restart or network call happens.
func TestHealthCheckValidate(t *testing.T) {
	good := HealthCheck{Kind: HealthKindHTTP, URL: "http://127.0.0.1:8080/healthz", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5}
	if err := good.validate(); err != nil {
		t.Fatalf("positive control (http): %v", err)
	}
	if err := (HealthCheck{Kind: HealthKindHTTP, URL: "https://[::1]/healthz", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5}).validate(); err != nil {
		t.Fatalf("positive control (http, ::1): %v", err)
	}
	if err := (HealthCheck{Kind: HealthKindUnitActive, SettleSeconds: 2}).validate(); err != nil {
		t.Fatalf("positive control (unit-active): %v", err)
	}
	if err := (HealthCheck{}).validate(); err != nil {
		t.Fatalf("positive control (none): %v", err)
	}
	cases := map[string]HealthCheck{
		"non-loopback ip":             {Kind: HealthKindHTTP, URL: "http://8.8.8.8/", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5},
		"non-loopback hostname":       {Kind: HealthKindHTTP, URL: "http://api.example.com/", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5},
		"localhost not accepted":      {Kind: HealthKindHTTP, URL: "http://localhost/", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5},
		"bad scheme":                  {Kind: HealthKindHTTP, URL: "ftp://127.0.0.1/", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5},
		"unparseable url":             {Kind: HealthKindHTTP, URL: "://not a url", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5},
		"no marker":                   {Kind: HealthKindHTTP, URL: "http://127.0.0.1/", ExpectStatus: 200, TimeoutSeconds: 5},
		"bad status":                  {Kind: HealthKindHTTP, URL: "http://127.0.0.1/", ExpectStatus: 0, BodyMarker: "ready", TimeoutSeconds: 5},
		"no timeout":                  {Kind: HealthKindHTTP, URL: "http://127.0.0.1/", ExpectStatus: 200, BodyMarker: "ready"},
		"timeout too long":            {Kind: HealthKindHTTP, URL: "http://127.0.0.1/", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 3600},
		"http carries settle_seconds": {Kind: HealthKindHTTP, URL: "http://127.0.0.1/", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5, SettleSeconds: 1},
		"unit-active no settle":       {Kind: HealthKindUnitActive},
		"unit-active settle too long": {Kind: HealthKindUnitActive, SettleSeconds: 1000},
		"unit-active carries url":     {Kind: HealthKindUnitActive, SettleSeconds: 2, URL: "http://127.0.0.1/"},
		"unknown kind":                {Kind: "shell", SettleSeconds: 2},
		"empty kind with fields":      {SettleSeconds: 2},
	}
	for name, h := range cases {
		if err := h.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Guard: a host administrator cannot even configure a
// non-loopback http healthcheck — ParseHostPolicy refuses the whole policy
// file at load time, before any job is ever checked.
func TestHostPolicyRefusesNonLoopbackHealthCheck(t *testing.T) {
	p := testPolicy()
	p.Targets[0].Health = HealthCheck{
		Kind: HealthKindHTTP, URL: "http://198.51.100.9/", ExpectStatus: 200, BodyMarker: "ready", TimeoutSeconds: 5,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("HostPolicy.Validate accepted a non-loopback http healthcheck")
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHostPolicy(b); err == nil {
		t.Fatal("ParseHostPolicy accepted a non-loopback http healthcheck")
	}
}

// Guard: ResolveHealth returns the healthcheck of whichever rule
// actually admitted the consumer for restart — the same kind, path prefix
// and Units match Check itself uses — and the zero value (no check) for
// anything that rule wouldn't have allowed to restart.
func TestResolveHealth(t *testing.T) {
	p := testPolicy()
	p.Targets[0].Health = HealthCheck{Kind: HealthKindUnitActive, SettleSeconds: 2}
	tgt := Target{
		Kind: TargetEnvFile, Path: "/etc/keep/app/app.env", Field: "STRIPE_KEY",
		Consumer: "systemd:app.service", Mode: 0o640, UID: 1001, GID: 1001,
	}
	if h := ResolveHealth(p, tgt); h.Kind != HealthKindUnitActive || h.SettleSeconds != 2 {
		t.Fatalf("matching rule: got %+v", h)
	}
	other := tgt
	other.Consumer = "systemd:other.service"
	if h := ResolveHealth(p, other); h != (HealthCheck{}) {
		t.Fatalf("consumer not allowlisted: got %+v, want zero value", h)
	}
	outside := tgt
	outside.Path = "/home/agent/.env"
	if h := ResolveHealth(p, outside); h != (HealthCheck{}) {
		t.Fatalf("path outside prefix: got %+v, want zero value", h)
	}
}

func TestParseHostPolicy(t *testing.T) {
	good := `{"version":1,"targets":[{"kind":"env-file","path_prefixes":["/etc/keep"],"fields":["STRIPE_KEY"]}],"agent_uids":[501],"agent_gids":[20],"uid_shared":false,"allow_exec":false,"exec_net_unenforced":false,"systemd_cred_plaintext_fallback":false,"max_deploys_per_hour":60}`
	p, err := ParseHostPolicy([]byte(good))
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if p.SystemdCredPlaintextFallback {
		t.Fatal("systemd plaintext fallback is on in a policy that says false")
	}
	// Threat model 7.4: the plaintext fallback is the administrator's
	// explicit choice, off unless the policy names it.
	on, err := ParseHostPolicy([]byte(strings.Replace(good, `"systemd_cred_plaintext_fallback":false`, `"systemd_cred_plaintext_fallback":true`, 1)))
	if err != nil || !on.SystemdCredPlaintextFallback {
		t.Fatalf("systemd plaintext fallback not read: %v", err)
	}
	off, err := ParseHostPolicy([]byte(strings.Replace(good, `"systemd_cred_plaintext_fallback":false,`, ``, 1)))
	if err != nil || off.SystemdCredPlaintextFallback {
		t.Fatalf("systemd plaintext fallback is not off by default: %v", err)
	}
	for name, s := range map[string]string{
		"unknown field":    strings.Replace(good, `"uid_shared"`, `"allow_all":true,"uid_shared"`, 1),
		"network kind":     strings.Replace(good, `"env-file"`, `"https"`, 1),
		"url prefix":       strings.Replace(good, `"/etc/keep"`, `"https://x"`, 1),
		"dotdot prefix":    strings.Replace(good, `"/etc/keep"`, `"/etc/keep/.."`, 1),
		"root prefix":      strings.Replace(good, `"/etc/keep"`, `"/"`, 1),
		"no rate limit":    strings.Replace(good, `60`, `0`, 1),
		"trailing object":  good + `{}`,
		"trailing bracket": good + `]`,
		"trailing brace":   good + `}`,
		"version 2":        strings.Replace(good, `"version":1`, `"version":2`, 1),
		"no fields":        strings.Replace(good, `,"fields":["STRIPE_KEY"]`, ``, 1),
		"echo field":       strings.Replace(good, `"STRIPE_KEY"`, `"NODE_OPTIONS"`, 1),
	} {
		if _, err := ParseHostPolicy([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadHostPolicyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := `{"version":1,"targets":[],"max_deploys_per_hour":1}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostPolicy(path, os.Getuid()); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if _, err := LoadHostPolicy(path, os.Getuid()+1); err == nil {
		t.Error("foreign owner accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // G302: the test needs a too-open file
		t.Fatal(err)
	}
	if _, err := LoadHostPolicy(path, os.Getuid()); err == nil {
		t.Error("group-readable policy accepted")
	}
	_ = os.Chmod(path, 0o600)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostPolicy(link, os.Getuid()); err == nil {
		t.Error("symlinked policy accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(testPolicy())
	j := deployJob(t)
	for i := 0; i < 2; i++ {
		if err := l.Allow(j, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	if err := l.Allow(j, t0.Add(3*time.Minute)); !errors.Is(err, ErrPolicy) {
		t.Fatalf("third deploy in an hour: %v", err)
	}
	v := j
	v.Action = ActionVerify
	if err := l.Allow(v, t0.Add(4*time.Minute)); err != nil {
		t.Fatalf("verify counted: %v", err)
	}
	if err := l.Allow(j, t0.Add(time.Hour+time.Second)); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func TestClassOf(t *testing.T) {
	for err, want := range map[error]ErrorClass{
		ErrSignature: ErrClassSignature, ErrReplay: ErrClassReplay, ErrExpired: ErrClassExpired,
		ErrWrongRunner: ErrClassWrongRunner, denied("x"): ErrClassPolicyDenied,
		invalid("x"): ErrClassInvalidJob, errors.New("other"): ErrClassInternal,
	} {
		if got := ClassOf(err); got != want || !errorClasses[got] {
			t.Errorf("%v: got %q want %q", err, got, want)
		}
	}
}

func TestErrorClassValid(t *testing.T) {
	for c := range errorClasses {
		if !c.Valid() {
			t.Fatalf("%q is in the closed set but not Valid", c)
		}
	}
	for _, bad := range []ErrorClass{"", "open /etc/shadow", "Internal", "internal "} {
		if bad.Valid() {
			t.Fatalf("%q must not be a valid class", bad)
		}
	}
}
