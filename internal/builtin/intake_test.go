package builtin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/intake/descriptor"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntakePrivateKeyIsSealedAtRest(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	p := New(pool, seal, sealer.Scope{Org: randID(t, "intake"), User: "alice"}, nil)
	key, err := p.intakeKeys(ctx)
	if err != nil {
		t.Fatal("initialize intake key")
	}
	defer key.Wipe()
	row, err := p.db.byVersion(ctx, p.scope, intakeKeySecretID, 1)
	if err != nil {
		t.Fatal("read intake envelope")
	}
	wire, err := json.Marshal(row.cipher)
	if err != nil {
		t.Fatal("encode storage probe")
	}
	var exposed bool
	secret.Expose(key, func(raw []byte) {
		exposed = bytes.Contains(row.cipher, raw)
		for _, part := range [][]byte{raw[:32], raw[32:]} {
			encoded, _ := json.Marshal(part)
			exposed = exposed || bytes.Contains(row.cipher, part) || bytes.Contains(wire, encoded)
		}
	})
	if exposed {
		t.Fatal("intake private key stored as plaintext")
	}
	// Positive control: the envelope must be recoverable by a new provider.
	again, err := New(pool, seal, p.scope, nil).intakeKeys(ctx)
	if err != nil {
		t.Fatal("intake key cannot be recovered after restart")
	}
	defer again.Wipe()
	var equal bool
	secret.Expose(key, func(a []byte) { secret.Expose(again, func(b []byte) { equal = bytes.Equal(a, b) }) })
	if !equal {
		t.Fatal("intake key changed after restart")
	}
}

func TestIntakeKeyReservedFromProvider(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	p := New(pool, seal, sealer.Scope{Org: randID(t, "reserved"), User: "alice"}, nil)
	key, err := p.intakeKeys(ctx)
	if err != nil {
		t.Fatal("initialize intake key")
	}
	defer key.Wipe()
	ref := provider.Ref{Path: intakeKeySecretID, Version: "1"}
	v, _, err := p.Resolve(ctx, ref)
	v.Wipe()
	if !errors.Is(err, provider.ErrInvalidRef) {
		t.Error("Resolve allowed reserved intake key")
	}
	_, err = p.Version(ctx, ref)
	if !errors.Is(err, provider.ErrInvalidRef) {
		t.Error("Version allowed reserved intake key")
	}
	_, err = p.Write(ctx, ref, key)
	if !errors.Is(err, provider.ErrInvalidRef) {
		t.Error("Write allowed reserved intake key")
	}
	if err = p.Disable(ctx, ref); !errors.Is(err, provider.ErrInvalidRef) {
		t.Error("Disable allowed reserved intake key")
	}
	if err = p.Erase(ctx, ref); !errors.Is(err, provider.ErrInvalidRef) {
		t.Error("Erase allowed reserved intake key")
	}
}

func TestIntakeKeyConcurrentInitialization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const n = 8
	pool := testPoolSized(t, n+1)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "race"), User: "alice"}
	// Hold the exclusive org lock until every caller has observed a missing
	// key and is waiting to seal its own candidate. This guarantees losers
	// exercise the insert-conflict fallback, independent of scheduling.
	blocker, err := pool.BeginTx(ctx, readCommitted)
	if err != nil {
		t.Fatal("begin initialization barrier")
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	var pid int
	if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid(), pg_advisory_xact_lock(hashtextextended($1, 0))`, levelLockKey(scope.Org)).Scan(&pid, new(any)); err != nil {
		t.Fatal("lock initialization barrier")
	}
	keys := make([]secret.Value, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() { defer wg.Done(); keys[i], errs[i] = New(pool, seal, scope, nil).intakeKeys(ctx) }()
	}
	for {
		var waiting int
		err := blocker.QueryRow(ctx, `SELECT count(*) FROM pg_locks AS waiting
			JOIN pg_locks AS held USING (locktype, database, classid, objid, objsubid)
			WHERE held.pid=$1 AND held.granted AND NOT waiting.granted AND held.locktype='advisory'`, pid).Scan(&waiting)
		if err != nil {
			t.Fatal("initializers did not reach barrier")
		}
		if waiting == n {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal("release initialization barrier")
	}
	wg.Wait()
	for i := range n {
		defer keys[i].Wipe()
		if errs[i] != nil {
			t.Fatal("concurrent initialization failed")
		}
	}
	for i := 1; i < n; i++ {
		var equal bool
		secret.Expose(keys[0], func(a []byte) { secret.Expose(keys[i], func(b []byte) { equal = bytes.Equal(a, b) }) })
		if !equal {
			t.Fatal("concurrent callers disagree on intake key")
		}
	}
}

func TestIntakeAcceptBoundCiphertext(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	var logs bytes.Buffer
	p := New(pool, seal, sealer.Scope{Org: randID(t, "accept"), User: "alice"}, slog.New(slog.NewJSONHandler(&logs, nil)))
	const request = "019a0000-0000-7000-8000-000000000001"
	metadata := descriptor.Metadata{SecretName: "sample", Scope: "org:sample", StoreName: "Primary", Class: "dev", RequestedBy: "user sample", Sponsor: "sponsor"}
	public, signing, sig, err := p.IntakeDescriptor(ctx, request, metadata)
	if err != nil {
		t.Fatal("initialize descriptor")
	}
	message := descriptor.Message(request, public, metadata)
	if !ed25519.Verify(signing, message, sig) {
		t.Fatal("descriptor signature invalid")
	}
	message[len(message)-1] ^= 1
	if ed25519.Verify(signing, message, sig) {
		t.Fatal("tampered descriptor accepted")
	}
	c := canary.New()
	plaintext := []byte(c.Value(1))
	defer clear(plaintext)
	if !c.In(string(plaintext)) {
		t.Fatal("canary detector positive control failed")
	}
	pk, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(public)
	if err != nil {
		t.Fatal("decode public key")
	}
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	sender, err := suite.NewSender(pk, []byte("keep/intake/v1\x00"+request))
	if err != nil {
		t.Fatal("sender")
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal("setup sender")
	}
	ct, err := sealer.Seal(plaintext, nil)
	if err != nil {
		t.Fatal("seal message")
	}
	wire, _ := json.Marshal(struct{ Enc, Ciphertext []byte }{enc, ct})
	if c.In(string(wire)) {
		t.Fatal("plaintext in intake transport")
	}
	tx, err := pool.BeginTx(ctx, readCommitted)
	if err != nil {
		t.Fatal("begin")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, _, _, err = p.AcceptIntake(ctx, tx, "019a0000-0000-7000-8000-000000000002", "sample", enc, ct)
	if err == nil {
		t.Fatal("ciphertext accepted for another request")
	}
	if c.In(fmt.Sprintf("%+v", err)) {
		t.Fatal("plaintext in error")
	}
	broken := append([]byte(nil), ct...)
	broken[len(broken)-1] ^= 1
	if _, _, _, err := p.AcceptIntake(ctx, tx, request, "sample", enc, broken); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	for _, path := range []string{intakeKeySecretID, fpKeySecretID, ""} {
		if _, _, _, err := p.AcceptIntake(ctx, tx, request, path, enc, ct); err == nil {
			t.Error("reserved intake path accepted")
		}
	}
	version, fp, length, err := p.AcceptIntake(ctx, tx, request, "sample", enc, ct)
	if err != nil {
		t.Fatal("accept ciphertext")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("commit")
	}
	row, err := p.db.byVersion(ctx, p.scope, "sample", 1)
	if err != nil {
		t.Fatal("read envelope")
	}
	persisted, _ := json.Marshal(struct{ Wrapped, Cipher []byte }{row.wrapped, row.cipher})
	if c.In(string(persisted)) || c.In(logs.String()) || c.In(fp) {
		t.Fatal("plaintext escaped intake zone")
	}
	v, _, err := p.Resolve(ctx, provider.Ref{Path: "sample", Version: version})
	if err != nil {
		t.Fatal("resolve accepted version")
	}
	defer v.Wipe()
	var equal bool
	secret.Expose(v, func(b []byte) { equal = bytes.Equal(b, plaintext) })
	if !equal || length != len(plaintext) {
		t.Fatal("accepted value mismatch")
	}
	key, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatal("fingerprint key")
	}
	defer key.Wipe()
	expected, err := fingerprint.Compute(key, v)
	if err != nil || fp != expected {
		t.Fatal("fingerprint mismatch")
	}
	rollback, err := pool.BeginTx(ctx, readCommitted)
	if err != nil {
		t.Fatal("begin rollback probe")
	}
	if _, _, _, err = p.AcceptIntake(ctx, rollback, request, "rolled-back", enc, ct); err != nil {
		_ = rollback.Rollback(ctx)
		t.Fatal("prepare rollback probe")
	}
	if err = rollback.Rollback(ctx); err != nil {
		t.Fatal("rollback probe")
	}
	if _, err = p.db.byVersion(ctx, p.scope, "rolled-back", 1); !errors.Is(err, errNotFound) {
		t.Fatal("intake version survived caller rollback")
	}
	if logs.Len() == 0 {
		t.Fatal("log capture not exercised")
	}
}

// An attacker can compute the entire HPKE schedule for a zero DH result.
// A valid tag under that schedule isolates the DH guard from GCM rejection.
func zeroDHIntakeCiphertext(t *testing.T, public, enc, info, plaintext []byte) []byte {
	t.Helper()
	kemSuite := []byte{'K', 'E', 'M', 0, 32}
	suite := []byte{'H', 'P', 'K', 'E', 0, 32, 0, 1, 0, 2}
	extract := func(sid []byte, salt []byte, label string, ikm []byte) []byte {
		input := append(append(append([]byte("HPKE-v1"), sid...), label...), ikm...)
		return hpke.KDF_HKDF_SHA256.Extract(input, salt)
	}
	expand := func(sid, prk []byte, label string, info []byte, size uint16) []byte {
		input := append(binary.BigEndian.AppendUint16(nil, size), []byte("HPKE-v1")...)
		input = append(append(append(input, sid...), label...), info...)
		return hpke.KDF_HKDF_SHA256.Expand(prk, input, uint(size))
	}
	eae := extract(kemSuite, nil, "eae_prk", make([]byte, 32))
	defer clear(eae)
	shared := expand(kemSuite, eae, "shared_secret", append(append([]byte(nil), enc...), public...), 32)
	defer clear(shared)
	context := append([]byte{0}, extract(suite, nil, "psk_id_hash", nil)...)
	context = append(context, extract(suite, nil, "info_hash", info)...)
	secret := extract(suite, shared, "secret", nil)
	defer clear(secret)
	key := expand(suite, secret, "key", context, 32)
	defer clear(key)
	nonce := expand(suite, secret, "base_nonce", context, 12)
	defer clear(nonce)
	aead, err := hpke.AEAD_AES256GCM.New(key)
	if err != nil {
		t.Fatal("construct zero-DH attacker cipher")
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	opened, err := aead.Open(nil, nonce, ct, nil)
	defer clear(opened)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatal("zero-DH tag positive control failed")
	}
	return ct
}

func intakeTestCiphertext(t *testing.T, public []byte, request string, plaintext []byte) (enc, ct []byte) {
	t.Helper()
	pk, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(public)
	if err != nil {
		t.Fatal("decode test receiver key")
	}
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	sender, err := suite.NewSender(pk, []byte("keep/intake/v1\x00"+request))
	if err != nil {
		t.Fatal("construct test sender")
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal("setup test sender")
	}
	ct, err = sealer.Seal(plaintext, nil)
	if err != nil {
		t.Fatal("encrypt test message")
	}
	return enc, ct
}

func TestIntakeRejectsLowOrderDH(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	p := New(pool, seal, sealer.Scope{Org: randID(t, "low-order"), User: "alice"}, nil)
	const request = "019a0000-0000-7000-8000-000000000001"
	public, _, _, err := p.IntakeDescriptor(ctx, request, descriptor.Metadata{})
	if err != nil {
		t.Fatal("initialize low-order descriptor")
	}
	plaintext := []byte(canary.New().Value(1))
	defer clear(plaintext)
	tx, err := pool.BeginTx(ctx, readCommitted)
	if err != nil {
		t.Fatal("begin low-order probe")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, point := range []byte{0, 1} {
		enc := make([]byte, 32)
		enc[0] = point
		ct := zeroDHIntakeCiphertext(t, public, enc, []byte("keep/intake/v1\x00"+request), plaintext)
		if _, _, _, err := p.AcceptIntake(ctx, tx, request, "sample", enc, ct); err == nil {
			t.Error("zero-DH ciphertext accepted")
		}
	}
	enc, ct := intakeTestCiphertext(t, public, request, plaintext)
	if _, _, _, err := p.AcceptIntake(ctx, tx, request, "sample", enc, ct); err != nil {
		t.Fatal("valid DH positive control rejected")
	}
}

func TestIntakeCiphertextStoreIsolation(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "cross-store")
	a := New(pool, seal, sealer.Scope{Org: org, User: "alice"}, nil)
	peers := []*Provider{
		New(pool, seal, sealer.Scope{Org: org, User: "bob"}, nil),
		New(pool, seal, sealer.Scope{Org: randID(t, "other-org"), User: "alice"}, nil),
	}
	const request = "019a0000-0000-7000-8000-000000000001"
	ak, _, _, err := a.IntakeDescriptor(ctx, request, descriptor.Metadata{})
	if err != nil {
		t.Fatal("initialize store A")
	}
	plaintext := []byte(canary.New().Value(1))
	defer clear(plaintext)
	enc, ct := intakeTestCiphertext(t, ak, request, plaintext)
	for _, b := range peers {
		bk, _, _, err := b.IntakeDescriptor(ctx, request, descriptor.Metadata{})
		if err != nil {
			t.Fatal("initialize store B")
		}
		tx, err := pool.BeginTx(ctx, readCommitted)
		if err != nil {
			t.Fatal("begin cross-store probe")
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, _, _, err := b.AcceptIntake(ctx, tx, request, "sample", enc, ct); err == nil {
			t.Error("store A ciphertext accepted by store B")
		}
		benc, bct := intakeTestCiphertext(t, bk, request, plaintext)
		if _, _, _, err := b.AcceptIntake(ctx, tx, request, "sample", benc, bct); err != nil {
			t.Fatal("store B positive control rejected")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal("rollback cross-store probe")
		}
	}
	tx, err := pool.BeginTx(ctx, readCommitted)
	if err != nil {
		t.Fatal("begin store A control")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, _, _, err := a.AcceptIntake(ctx, tx, request, "sample", enc, ct); err != nil {
		t.Fatal("store A positive control rejected")
	}
}

// Historical Write used Name=Path even for this formerly unreserved ID.
// A valid attacker-chosen bundle must never become a server receiver key.
func TestIntakeRejectsUserCreatedKey(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	p := New(pool, seal, sealer.Scope{Org: randID(t, "legacy-key"), User: "alice"}, nil)
	_, sk, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal("generate attacker key")
	}
	raw, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal("encode attacker key")
	}
	defer clear(raw)
	_, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal("generate attacker signer")
	}
	defer clear(signer)
	bundle := append(raw, signer...)
	defer clear(bundle)
	key := secret.New(bundle)
	defer key.Wipe()
	ref := sealer.Ref{Store: p.scope, SecretID: intakeKeySecretID, Name: intakeKeySecretID, Version: "1"}
	envelope, err := seal.Seal(ctx, ref, key)
	if err != nil {
		t.Fatal("seal historical user write")
	}
	if inserted, err := p.db.insertIfAbsent(ctx, p.scope, intakeKeySecretID, intakeKeySecretID, 1, envelope); err != nil || !inserted {
		t.Fatal("persist historical user write")
	}
	const request = "019a0000-0000-7000-8000-000000000001"
	if _, _, _, err := p.IntakeDescriptor(ctx, request, descriptor.Metadata{}); err == nil {
		t.Error("user-created intake key accepted by descriptor")
	}
	// Fingerprint key is a positive prerequisite, so rejection cannot come
	// from a missing fingerprint key later in AcceptIntake.
	fk, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatal("initialize fingerprint prerequisite")
	}
	fk.Wipe()
	public, err := sk.Public().MarshalBinary()
	if err != nil {
		t.Fatal("encode attacker public key")
	}
	plaintext := []byte(canary.New().Value(1))
	defer clear(plaintext)
	enc, ct := intakeTestCiphertext(t, public, request, plaintext)
	tx, err := pool.BeginTx(ctx, readCommitted)
	if err != nil {
		t.Fatal("begin legacy-key probe")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, _, _, err := p.AcceptIntake(ctx, tx, request, "sample", enc, ct); err == nil {
		t.Error("user-created intake key accepted by receiver")
	}
	// A metadata-only change must not confer provenance: Name is in AAD.
	if _, err := tx.Exec(ctx, `UPDATE keep_envelope SET name=$1 WHERE store_org=$2 AND secret_id=$3`, "keep/server-intake-key/v1", p.scope.Org, intakeKeySecretID); err != nil {
		t.Fatal("prepare metadata forgery")
	}
	if _, _, _, err := p.AcceptIntake(ctx, tx, request, "sample", enc, ct); err == nil {
		t.Error("metadata-forged intake key accepted")
	}
}

// Count the caller transaction's operations to prove validation precedes
// backend work; invalid GCM alone would mask missing size/UUID guards.
type intakeProbeTx struct {
	pgx.Tx
	calls int
}

func (tx *intakeProbeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.calls++
	return tx.Tx.Exec(ctx, sql, args...)
}
func (tx *intakeProbeTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.calls++
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func TestIntakeInputGuards(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	p := New(pool, seal, sealer.Scope{Org: randID(t, "input-guards"), User: "alice"}, nil)
	const request = "019a0000-0000-7000-8000-000000000001"
	public, _, _, err := p.IntakeDescriptor(ctx, request, descriptor.Metadata{})
	if err != nil {
		t.Fatal("initialize input guard descriptor")
	}
	plaintext := []byte(canary.New().Value(1))
	defer clear(plaintext)
	enc, ct := intakeTestCiphertext(t, public, request, plaintext)
	tx, err := pool.BeginTx(ctx, readCommitted)
	if err != nil {
		t.Fatal("begin input guard probe")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	probe := &intakeProbeTx{Tx: tx}
	invalidIDs := []string{"bad", "019a0000000070008000000000000001", "{019a0000-0000-7000-8000-000000000001}", "urn:uuid:019a0000-0000-7000-8000-000000000001", "019A0000-0000-7000-8000-000000000001", "019a0000-0000-4000-8000-000000000001", "019a0000-0000-7000-0000-000000000001"}
	for _, id := range invalidIDs {
		if _, _, _, err := p.IntakeDescriptor(ctx, id, descriptor.Metadata{}); err == nil {
			t.Error("invalid request descriptor accepted")
		}
		probe.calls = 0
		if _, _, _, err := p.AcceptIntake(ctx, probe, id, "sample", enc, ct); err == nil || probe.calls != 0 {
			t.Error("invalid request reached backend")
		}
	}
	for _, input := range []struct{ enc, ct []byte }{{enc[:31], ct}, {append(append([]byte(nil), enc...), 0), ct}, {enc, ct[:15]}, {enc, make([]byte, 1048593)}} {
		probe.calls = 0
		if _, _, _, err := p.AcceptIntake(ctx, probe, request, "sample", input.enc, input.ct); err == nil || probe.calls != 0 {
			t.Error("invalid intake size reached backend")
		}
	}
	p.testSetUnavailable(true)
	probe.calls = 0
	if _, _, _, err := p.AcceptIntake(ctx, probe, request, "sample", enc, ct); err == nil || probe.calls != 0 {
		t.Error("unavailable intake reached backend")
	}
	p.testSetUnavailable(false)
	if _, _, _, err := p.AcceptIntake(ctx, probe, request, "sample", enc, ct); err != nil || probe.calls == 0 {
		t.Fatal("valid input positive control rejected")
	}
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND mode='ShareLock' AND granted)`).Scan(&locked); err != nil || !locked {
		t.Fatal("intake shared key-level lock missing")
	}
	// Inclusive limits: empty plaintext (tag only) and exactly 1 MiB.
	for _, n := range []int{0, 1048576} {
		value := make([]byte, n)
		enc, ct := intakeTestCiphertext(t, public, request, value)
		if _, _, length, err := p.AcceptIntake(ctx, tx, request, "boundary", enc, ct); err != nil || length != n {
			t.Fatal("valid size boundary rejected")
		}
		clear(value)
	}
}
