package fingerprint

import (
	"bytes"
	"crypto/md5" //nolint:gosec // guard (b) compares the tag against weak unkeyed digests on purpose
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // guard (b), as above
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// testKeyBytes is a fixed, public test key (0x00..0x1f). It exists only to
// pin the known-answer vector below.
func testKeyBytes() []byte {
	b := make([]byte, KeySize)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func mustKey(t *testing.T, id string, b []byte) Key {
	t.Helper()
	k, err := NewKey(id, b)
	if err != nil {
		t.Fatalf("NewKey(%q): %v", id, err)
	}
	return k
}

func mustGenerate(t *testing.T, id string) Key {
	t.Helper()
	k, err := GenerateKey(id)
	if err != nil {
		t.Fatalf("GenerateKey(%q): %v", id, err)
	}
	return k
}

func mustCompute(t *testing.T, k Key, v secret.Value) string {
	t.Helper()
	fp, err := Compute(k, v)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	return fp
}

func randomValue(t *testing.T, n int) secret.Value {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return secret.New(b)
}

// TestKnownAnswer pins the wire format: domain string, 0x00 separator,
// HMAC-SHA256, 10-byte truncation, lowercase unpadded base32. The expected
// strings were computed independently (Python hmac/hashlib/base64), not by
// this package, so a silent format change fails here.
func TestKnownAnswer(t *testing.T) {
	k := mustKey(t, "st1", testKeyBytes())
	cases := []struct {
		value, want string
	}{
		{"correct horse battery staple", "kfp1:st1:arm747oibqg7wc5j"},
		{"", "kfp1:st1:sofvq7gepdchnq52"},
	}
	for _, c := range cases {
		if got := mustCompute(t, k, secret.New([]byte(c.value))); got != c.want {
			t.Errorf("Compute(len=%d) = %s, want %s", len(c.value), got, c.want)
		}
	}
}

// Guard (a): one value in two stores gives two unrelated fingerprints, and
// the same store gives the same fingerprint every time (so (a) is not
// satisfied by accident, e.g. by randomness).
func TestGuardA_SameValueTwoStoresDiffer(t *testing.T) {
	a := mustGenerate(t, "storea")
	b := mustGenerate(t, "storeb")
	for i := 0; i < 64; i++ {
		v := randomValue(t, 1+i)
		fa, fb := mustCompute(t, a, v), mustCompute(t, b, v)
		if tag(fa) == tag(fb) {
			t.Fatalf("value #%d: same tag %s under two different store keys", i, tag(fa))
		}
		if again := mustCompute(t, a, v); again != fa {
			t.Fatalf("value #%d: not deterministic under one key: %s then %s", i, fa, again)
		}
	}
	// Same key bytes under two ids: the tag is a function of the key bytes,
	// not of the id, and must not change — the id only names the key.
	kb := testKeyBytes()
	x, y := mustKey(t, "x1", kb), mustKey(t, "y1", kb)
	v := secret.New([]byte("v"))
	if tag(mustCompute(t, x, v)) != tag(mustCompute(t, y, v)) {
		t.Fatal("tag depends on the key id, not only on the key bytes")
	}
}

// Guard (b): the fingerprint is not an unkeyed digest of the value under any
// common hash, with or without the domain prefix, in any truncation or
// common encoding.
func TestGuardB_NotABareHash(t *testing.T) {
	k := mustGenerate(t, "st1")
	for i := 0; i < 64; i++ {
		raw := make([]byte, 1+i)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		fp := mustCompute(t, k, secret.New(raw))
		tg := tag(fp)
		tb, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(tg))
		if err != nil {
			t.Fatalf("tag is not base32: %v", err)
		}
		for name, d := range unkeyedDigests(raw) {
			if bytes.Contains(d, tb) {
				t.Fatalf("tag bytes found inside unkeyed %s of the value", name)
			}
			for enc, s := range encodings(d) {
				if strings.Contains(strings.ToLower(s), tg) {
					t.Fatalf("tag found inside %s(%s(value))", enc, name)
				}
			}
		}
	}
}

func unkeyedDigests(v []byte) map[string][]byte {
	dv := append([]byte(domain+"\x00"), v...)
	s256, s256d := sha256.Sum256(v), sha256.Sum256(dv)
	s512, s512d := sha512.Sum512(v), sha512.Sum512(dv)
	s1, s1d := sha1.Sum(v), sha1.Sum(dv) //nolint:gosec // guard (b)
	m5, m5d := md5.Sum(v), md5.Sum(dv)   //nolint:gosec // guard (b)
	return map[string][]byte{
		"sha256": s256[:], "sha256+domain": s256d[:],
		"sha512": s512[:], "sha512+domain": s512d[:],
		"sha1": s1[:], "sha1+domain": s1d[:],
		"md5": m5[:], "md5+domain": m5d[:],
	}
}

// Guard (c): every computed fingerprint matches the published format, and
// the format rejects near misses.
func TestGuardC_Format(t *testing.T) {
	k := mustGenerate(t, "a0")
	for i := 0; i < 64; i++ {
		fp := mustCompute(t, k, randomValue(t, i))
		if !Valid(fp) {
			t.Fatalf("computed fingerprint %q fails Valid", fp)
		}
		p, err := Parse(fp)
		if err != nil || p.KeyID != "a0" || p.Tag != tag(fp) {
			t.Fatalf("Parse(%q) = %+v, %v", fp, p, err)
		}
	}
	good := "kfp1:st1:arm747oibqg7wc5j"
	if !Valid(good) {
		t.Fatalf("reference fingerprint rejected")
	}
	bad := []string{
		"",
		"kfp2:st1:arm747oibqg7wc5j",               // version
		"KFP1:st1:arm747oibqg7wc5j",               // prefix case
		"kfp1:st1:ARM747OIBQG7WC5J",               // tag case
		"kfp1:st1:arm747oibqg7wc5",                // 15 chars
		"kfp1:st1:arm747oibqg7wc5jq",              // 17 chars
		"kfp1:st1:arm747oibqg7wc5j======",         // padding
		"kfp1:st1:arm747oibqg7wc01",               // not base32 (0, 1)
		"kfp1:st1:arm747oibqg7wc89",               // not base32 (8, 9)
		"kfp1::arm747oibqg7wc5j",                  // empty key id
		"kfp1:ST1:arm747oibqg7wc5j",               // key id case
		"kfp1:st-1:arm747oibqg7wc5j",              // key id charset
		"kfp1:abcdefghijklmnopq:arm747oibqg7wc5j", // key id 17 chars
		"kfp1:st1:x:arm747oibqg7wc5j",             // extra field
		"kfp1:st1:arm747oibqg7wc5j\n",             // trailing newline
		" kfp1:st1:arm747oibqg7wc5j",              // leading space
		"sha256:arm747oibqg7wc5j",                 // not ours at all
	}
	for _, s := range bad {
		if Valid(s) {
			t.Errorf("Valid(%q) = true, want false", s)
		}
		if _, err := Parse(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%q) error = %v, want ErrMalformed", s, err)
		}
	}
}

func TestKeyValidation(t *testing.T) {
	for _, id := range []string{"", "A", "a:b", "a-b", "abcdefghijklmnopq"} {
		if _, err := NewKey(id, testKeyBytes()); !errors.Is(err, ErrKeyID) {
			t.Errorf("NewKey(id=%q) error = %v, want ErrKeyID", id, err)
		}
	}
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewKey("k1", make([]byte, n)); !errors.Is(err, ErrKeySize) {
			t.Errorf("NewKey(%d bytes) error = %v, want ErrKeySize", n, err)
		}
	}
	// An all-zero key is a key nobody generated: refuse it like an empty one.
	if _, err := NewKey("k1", make([]byte, KeySize)); !errors.Is(err, ErrKeySize) {
		t.Errorf("NewKey(all-zero) error = %v, want ErrKeySize", err)
	}
}

// The zero Key would make HMAC an unkeyed digest. Compute must refuse it.
func TestZeroKeyRefused(t *testing.T) {
	var k Key
	if _, err := Compute(k, secret.New([]byte("v"))); !errors.Is(err, ErrZeroKey) {
		t.Fatalf("Compute(zero Key) error = %v, want ErrZeroKey", err)
	}
	w := mustGenerate(t, "k1")
	w.Wipe()
	if _, err := Compute(w, secret.New([]byte("v"))); !errors.Is(err, ErrZeroKey) {
		t.Fatalf("Compute(wiped Key) error = %v, want ErrZeroKey", err)
	}
}

// NewKey copies its input: wiping or reusing the caller's buffer does not
// change the key.
func TestNewKeyCopies(t *testing.T) {
	b := testKeyBytes()
	k := mustKey(t, "st1", b)
	for i := range b {
		b[i] = 0xff
	}
	if got := mustCompute(t, k, secret.New([]byte("correct horse battery staple"))); got != "kfp1:st1:arm747oibqg7wc5j" {
		t.Fatalf("key changed with caller's buffer: %s", got)
	}
}

// Leak: no formatting path of a Key renders the key bytes, in any common
// encoding; only the id is shown.
func TestKeyNeverPrinted(t *testing.T) {
	k := mustGenerate(t, "st1")
	var kb []byte
	ExposeKey(k, func(b []byte) { kb = append([]byte(nil), b...) })
	defer func() {
		for i := range kb {
			kb[i] = 0
		}
	}()

	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))
	log.Info("key", "k", k, "kp", &k)
	js, _ := json.Marshal(struct{ K Key }{k})
	txt, _ := k.MarshalText()

	outputs := map[string]string{
		"%v": fmt.Sprintf("%v", k), "%+v": fmt.Sprintf("%+v", k), "%#v": fmt.Sprintf("%#v", k),
		"%s": fmt.Sprintf("%s", k), "%q": fmt.Sprintf("%q", k), "%x": fmt.Sprintf("%x", k),
		"%X": fmt.Sprintf("%X", k), "%v ptr": fmt.Sprintf("%v", &k), "%+v struct": fmt.Sprintf("%+v", struct{ K Key }{k}),
		"json": string(js), "text": string(txt), "slog": logBuf.String(),
		"String": k.String(), "err": fmt.Errorf("wrap %v", k).Error(),
	}
	for name, out := range outputs {
		for enc, s := range encodings(kb) {
			if strings.Contains(strings.ToLower(out), strings.ToLower(s)) {
				t.Errorf("%s output contains the key in %s encoding: %q", name, enc, out)
			}
		}
		if bytes.Contains([]byte(out), kb) {
			t.Errorf("%s output contains the raw key bytes", name)
		}
	}
	if !strings.Contains(k.String(), "st1") {
		t.Errorf("String() = %q, want it to name the key id", k.String())
	}
	if err := json.Unmarshal([]byte(`"x"`), &k); err == nil {
		t.Error("Key decoded from JSON; it must only be built by NewKey/GenerateKey")
	}
}

// Leak: Parse never echoes its input in an error — callers do pass the wrong
// string to it, and the wrong string may be a value.
func TestParseErrorDoesNotEchoInput(t *testing.T) {
	canary := "kfp1:" + hex.EncodeToString(testKeyBytes())
	_, err := Parse(canary)
	if err == nil {
		t.Fatal("Parse accepted a malformed string")
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), hex.EncodeToString(testKeyBytes())) {
		t.Fatalf("Parse error echoes its input: %v", err)
	}
}

// Leak: the fingerprint carries no encoding of the value itself.
func TestFingerprintDoesNotContainValue(t *testing.T) {
	k := mustGenerate(t, "st1")
	for i := 0; i < 32; i++ {
		raw := make([]byte, 6+i)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		fp := mustCompute(t, k, secret.New(raw))
		for enc, s := range encodings(raw) {
			if strings.Contains(strings.ToLower(fp), strings.ToLower(s)) {
				t.Fatalf("fingerprint contains the value in %s encoding", enc)
			}
		}
	}
}

func encodings(b []byte) map[string]string {
	return map[string]string{
		"raw":       string(b),
		"hex":       hex.EncodeToString(b),
		"base64":    base64.StdEncoding.EncodeToString(b),
		"base64raw": base64.RawStdEncoding.EncodeToString(b),
		"base64url": base64.RawURLEncoding.EncodeToString(b),
		"base32":    base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b),
	}
}

func tag(fp string) string { return fp[strings.LastIndexByte(fp, ':')+1:] }
