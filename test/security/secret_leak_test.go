// Package security holds an independent attack suite against code already
// merged to main (MR !1–!6). It is written from outside every package it
// attacks, using only exported API — the same vantage point an attacker or
// a careless caller elsewhere in the codebase would have. It does not
// replace the developers' own white-box tests; it exists to catch what a
// same-package test cannot see: a caller composing the type with
// encoding/gob, reflect, panic/recover, or a generic interface dispatch the
// package author did not anticipate.
//
// See CONTRIBUTING.md and the threat model doc
// (ca015950-a138-416f-accd-7915631eaab0) §4.4 for the contract this file
// tests: a secret.Value must never surface its plaintext through any
// formatting, encoding, or panic path.
package security

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// TestSecretValue_StdlibLogPackage attacks secret.Value through the
// standard "log" package (not slog) — a plain log.Logger calls fmt.Sprint
// internally, a different call path than slog's LogValue/Format dispatch
// that pkg/secret's own tests exercise.
func TestSecretValue_StdlibLogPackage(t *testing.T) {
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	logger.Println("event", v)
	logger.Printf("event %v %s %q", v, v, v)
	logger.Print("event ", v)

	out := buf.String()
	if c.In(out) {
		t.Fatalf("secret.Value leaked through the stdlib log package: %q", out)
	}
	if !strings.Contains(out, secret.Redacted) {
		t.Errorf("stdlib log output never shows the redaction marker: %q", out)
	}
}

// TestSecretValue_PlainFmtPrint attacks the print family that takes no
// format string at all (Print/Println/Sprint), as opposed to
// Printf/Sprintf which pkg/secret's own tests already cover.
func TestSecretValue_PlainFmtPrint(t *testing.T) {
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))

	outputs := map[string]string{
		"Sprint":   fmt.Sprint(v),
		"Sprintln": fmt.Sprintln(v),
		"Sprint&":  fmt.Sprint(&v),
	}
	var buf bytes.Buffer
	fmt.Fprint(&buf, v)
	fmt.Fprintln(&buf, v)
	outputs["Fprint"] = buf.String()

	for name, out := range outputs {
		if c.In(out) {
			t.Errorf("%s leaked the value: %q", name, out)
		}
	}
}

// TestSecretValue_Gob attacks the one encoder pkg/secret's own tests never
// exercise: encoding/gob, which — unlike encoding/json — has no MarshalXXX
// hook on Value at all. Its safety here rests entirely on gob's own
// documented behavior of skipping unexported struct fields, which is a
// property of the standard library, not of this package: a future Go
// version or a caller using gob.Register with an interface could change
// that. The test locks in the current behavior so a change is caught.
func TestSecretValue_Gob(t *testing.T) {
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	container := struct{ V secret.Value }{v}
	if err := enc.Encode(container); err != nil {
		// gob refusing to encode a type with no exported fields is an
		// acceptable outcome too: either way, nothing leaked.
		t.Logf("gob.Encode refused (acceptable — no leak either way): %v", err)
		return
	}

	wire := buf.Bytes()
	if c.In(string(wire)) {
		t.Fatalf("secret.Value leaked into gob wire bytes: %x", wire)
	}

	var decoded struct{ V secret.Value }
	if err := gob.NewDecoder(bytes.NewReader(wire)).Decode(&decoded); err != nil {
		t.Fatalf("decode of our own encoding failed: %v", err)
	}
	if !decoded.V.IsZero() {
		t.Errorf("gob round-trip reconstructed a non-zero value out of an unexported field — "+
			"decoded.V.Len()=%d; a secret.Value must never be reconstructable through gob without "+
			"going through secret.New", decoded.V.Len())
	}
}

// TestSecretValue_XML attacks encoding/xml, which — like gob — has no
// dedicated hook on Value and, unlike json, does not call MarshalText for
// an attribute value in every code path. This checks the element-content
// path (xml.Marshal uses TextMarshaler where the field is a chardata-like
// leaf).
func TestSecretValue_XML(t *testing.T) {
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))

	type doc struct {
		V secret.Value `xml:"v"`
	}
	out, err := xml.Marshal(doc{V: v})
	if err != nil {
		t.Logf("xml.Marshal refused (acceptable): %v", err)
		return
	}
	if c.In(string(out)) {
		t.Fatalf("secret.Value leaked into XML output: %s", out)
	}
}

// TestSecretValue_PanicRecover attacks the panic/recover path directly —
// panicking with the Value itself (not a string built from it), then
// formatting whatever recover() returns. This is the same shape of attack
// as internal/api's TestPanicRecoveryDoesNotLeakCanary, but aimed at the
// type itself rather than at the HTTP middleware that wraps it.
func TestSecretValue_PanicRecover(t *testing.T) {
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))

	rec := func() (r any) {
		defer func() { r = recover() }()
		panic(v)
	}()

	out := fmt.Sprintf("%v / %+v / %#v", rec, rec, rec)
	if c.In(out) {
		t.Fatalf("panic(secret.Value) leaked through recover()+fmt: %q", out)
	}
}

// TestSecretValue_ReflectPrintPath attacks fmt's reflection-based
// formatting entry points directly: reflect.ValueOf(v) fed back into
// Sprintf, and a fmt verb (%v) on an interface{} holding the Value inside a
// slice/map, where Go's fmt package walks the container generically rather
// than calling Value.Format() at the top level.
func TestSecretValue_ReflectPrintPath(t *testing.T) {
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))

	rv := reflect.ValueOf(v)
	out1 := fmt.Sprintf("%v", rv)

	slice := []secret.Value{v, secret.New([]byte(c.Value(2)))}
	out2 := fmt.Sprintf("%v", slice)

	m := map[string]secret.Value{"k": v}
	out3 := fmt.Sprintf("%v", m)

	arr := [2]secret.Value{v, v}
	out4 := fmt.Sprintf("%v", arr)

	iface := []any{v, 1, "x"}
	out5 := fmt.Sprintf("%v", iface)

	for name, out := range map[string]string{
		"reflect.Value": out1, "slice": out2, "map": out3, "array": out4, "interface-slice": out5,
	} {
		if c.In(out) {
			t.Errorf("%s leaked the value: %q", name, out)
		}
	}
}

// TestSecretValue_NestedAndEmbedded attacks Value wrapped inside deeper
// composition than pkg/secret's own single-field struct test: a pointer
// field, an embedded (anonymous) field, and a value stored behind an
// interface field of a struct — three shapes where a naive DIY formatter
// (as opposed to fmt's own dispatch) could plausibly forget to redact.
func TestSecretValue_NestedAndEmbedded(t *testing.T) {
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))

	type embedded struct {
		secret.Value
		Name string
	}
	type withIface struct {
		V   any
		Ptr *secret.Value
	}

	e := embedded{Value: v, Name: "n"}
	w := withIface{V: v, Ptr: &v}

	outputs := []string{
		fmt.Sprintf("%v", e), fmt.Sprintf("%+v", e), fmt.Sprintf("%#v", e),
		fmt.Sprintf("%v", w), fmt.Sprintf("%+v", w),
	}
	js, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("json.Marshal(withIface): %v", err)
	}
	outputs = append(outputs, string(js))

	var sb strings.Builder
	slog.New(slog.NewJSONHandler(&sb, nil)).Info("x", "e", e, "w", w)
	outputs = append(outputs, sb.String())

	for i, out := range outputs {
		if c.In(out) {
			t.Errorf("output #%d leaked the value: %q", i, out)
		}
	}
}

// TestSecretValue_DecodeAttacksRefused independently re-verifies R-CAR
// "cannot decode from text": every exported decode entry point must
// refuse, across formats pkg/secret's own test (JSON only) does not cover.
func TestSecretValue_DecodeAttacksRefused(t *testing.T) {
	var v secret.Value
	if err := v.UnmarshalText([]byte("attacker-controlled")); err == nil {
		t.Error("UnmarshalText must refuse to decode a value from text")
	}
	if err := v.UnmarshalJSON([]byte(`"attacker-controlled"`)); err == nil {
		t.Error("UnmarshalJSON must refuse to decode a value from text")
	}
	if !v.IsZero() {
		t.Error("a failed decode attempt must not leave a non-zero value behind")
	}
}

// TestLeakDetectorCanFail_Independent proves this file's own canary
// detector is not vacuous, independently of pkg/secret's identical-purpose
// test — written fresh rather than trusted because it was already green
// elsewhere (a check that has never been seen to fail is not a check).
func TestLeakDetectorCanFail_Independent(t *testing.T) {
	c := canary.New()
	if !c.In("prefix " + c.Value(1) + " suffix") {
		t.Fatal("canary detector did not flag its own raw value")
	}
	if !c.In(fmt.Sprintf("%x", c.Value(1))) {
		t.Fatal("canary detector did not flag its own hex-encoded value")
	}
}
