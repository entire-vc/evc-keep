package runnerproto

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func discoverJob(t testing.TB) Job {
	return Job{JobID: newJobID(t), OrgID: "acme", RunnerID: "runner-1",
		Secret: SecretRef{StoreID: "store-1", Provider: ProviderBuiltin}, Action: ActionDiscover,
		IssuedAt: t0, NotAfter: t0.Add(5 * time.Minute), Nonce: bytes.Repeat([]byte{7}, NonceSize)}
}

func TestDiscoverJobValidateAndRoundTrip(t *testing.T) {
	j := discoverJob(t)
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := EncodeJob(j)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeJob(b)
	if err != nil || !reflect.DeepEqual(got, j) {
		t.Fatalf("round trip: %v", err)
	}
	if !j.NeedsFingerprintKey() || j.NeedsValue() {
		t.Fatal("discover takes the key and no value")
	}
	// Every field a discover job must not carry is refused, one at a time.
	bad := map[string]func(*Job){
		"job id":      func(x *Job) { x.JobID = "not-a-uuid" },
		"name":        func(x *Job) { x.Secret.Name = "a" },
		"scope":       func(x *Job) { x.Secret.Scope = "prod" },
		"version":     func(x *Job) { x.ExpectedVersion = "1" },
		"fingerprint": func(x *Job) { x.ExpectedFingerprint = testFP },
		"target":      func(x *Job) { x.Target = Target{Path: "/etc/x"} },
		"consumer":    func(x *Job) { x.Target.Consumer = "systemd:a" },
		"exec":        func(x *Job) { x.Exec = &Exec{TemplateID: "t"} },
		"provider":    func(x *Job) { x.Secret.Provider = "vault" },
		"store":       func(x *Job) { x.Secret.StoreID = "" },
		"nonce":       func(x *Job) { x.Nonce = x.Nonce[:3] },
		"ttl":         func(x *Job) { x.NotAfter = x.IssuedAt.Add(MaxJobTTL + time.Second) },
	}
	for name, mod := range bad {
		x := discoverJob(t)
		mod(&x)
		if x.Validate() == nil {
			t.Errorf("discover job with %s accepted", name)
		}
	}
	// The other actions still refuse the empty fields discover leaves empty.
	for _, a := range []Action{ActionDeploy, ActionVerify} {
		x := deployJob(t)
		x.Action = a
		x.Secret.Name, x.Secret.Scope, x.ExpectedVersion, x.ExpectedFingerprint = "", "", "", ""
		if x.Validate() == nil {
			t.Errorf("%s job with empty secret fields accepted", a)
		}
	}
	x := deployJob(t)
	x.Action, x.Target, x.Exec = ActionExec, Target{}, &Exec{TemplateID: "t1", Digest: strings.Repeat("a", 64)}
	x.Secret.Name = ""
	if x.Validate() == nil {
		t.Error("exec job with empty name accepted")
	}
}

// Name and target tags are absent, not empty, in a discover job's encoding.
func TestDiscoverJobEncodingOmitsSecretAndTarget(t *testing.T) {
	b, err := EncodeJob(discoverJob(t))
	if err != nil {
		t.Fatal(err)
	}
	good, err := DecodeJob(b)
	if err != nil {
		t.Fatal(err)
	}
	// The exact canonical bytes: no secret and no target tag at all.
	var want encoder
	want.b.WriteString(jobDomain)
	want.str(tagJobID, good.JobID)
	want.str(tagOrgID, good.OrgID)
	want.str(tagRunnerID, good.RunnerID)
	want.str(tagStoreID, good.Secret.StoreID)
	want.str(tagProvider, good.Secret.Provider)
	want.str(tagAction, string(ActionDiscover))
	want.i64(tagIssuedAt, good.IssuedAt.Unix())
	want.i64(tagNotAfter, good.NotAfter.Unix())
	want.field(tagNonce, good.Nonce)
	if !bytes.Equal(b, want.b.Bytes()) {
		t.Fatal("discover job encoding carries secret or target tags")
	}
	// Re-encode with an empty name tag spliced in: non-canonical.
	var e encoder
	e.b.WriteString(jobDomain)
	e.str(tagJobID, good.JobID)
	e.str(tagOrgID, good.OrgID)
	e.str(tagRunnerID, good.RunnerID)
	e.str(tagStoreID, good.Secret.StoreID)
	e.str(tagProvider, good.Secret.Provider)
	e.str(tagSecretName, "")
	e.str(tagAction, string(ActionDiscover))
	e.i64(tagIssuedAt, good.IssuedAt.Unix())
	e.i64(tagNotAfter, good.NotAfter.Unix())
	e.field(tagNonce, good.Nonce)
	if _, err := DecodeJob(e.b.Bytes()); err == nil {
		t.Fatal("discover job with an empty name tag decoded")
	}
}

func TestDiscoverIsDeniedByHostPolicyUntilEnabled(t *testing.T) {
	if err := testPolicy().Validate(); err != nil {
		t.Fatalf("control: the test policy must be valid: %v", err)
	}
	if err := Check(discoverJob(t), testPolicy()); err == nil {
		t.Fatal("discover allowed with no discovery section")
	}
}

func TestDiscoverKeyInfoHasItsOwnDomain(t *testing.T) {
	j := discoverJob(t)
	d, v := DiscoverKeyInfo(j), VerifyKeyInfo(j)
	if bytes.Equal(d, v) || !bytes.HasPrefix(d, []byte("keep/fingerprint-key/discover/v1\x00")) {
		t.Fatal("discover key info must have its own domain")
	}
	for name, mod := range map[string]func(*Job){
		"job id": func(x *Job) { x.JobID = newJobID(t) },
		"org":    func(x *Job) { x.OrgID = "other-org" },
		"runner": func(x *Job) { x.RunnerID = "other-runner" },
		"store":  func(x *Job) { x.Secret.StoreID = "other-store" },
	} {
		o := j
		mod(&o)
		if bytes.Equal(d, DiscoverKeyInfo(o)) {
			t.Errorf("%s not bound", name)
		}
	}
	k := j
	k.Nonce = append([]byte{1}, k.Nonce[1:]...)
	if bytes.Equal(d, DiscoverKeyInfo(k)) {
		t.Fatal("nonce not bound")
	}
	k = j
	k.NotAfter = k.NotAfter.Add(time.Second)
	if bytes.Equal(d, DiscoverKeyInfo(k)) {
		t.Fatal("window not bound")
	}
}

// DiscoverResult is closed: a test walks the type and fails on an added field.
func TestDiscoverResultIsClosed(t *testing.T) {
	want := map[string][]string{"DiscoverResult": {"OK", "ErrorClass", "Findings"}, "DiscoverFinding": {"Path", "Name", "Fingerprint", "Len"}}
	for name, typ := range map[string]reflect.Type{"DiscoverResult": reflect.TypeOf(DiscoverResult{}), "DiscoverFinding": reflect.TypeOf(DiscoverFinding{})} {
		var got []string
		for i := range typ.NumField() {
			got = append(got, typ.Field(i).Name)
			switch typ.Field(i).Type.Kind() {
			case reflect.String, reflect.Bool, reflect.Int, reflect.Slice:
			default:
				t.Errorf("%s.%s has an unexpected kind", name, typ.Field(i).Name)
			}
		}
		if !reflect.DeepEqual(got, want[name]) {
			t.Errorf("%s fields = %v, want %v", name, got, want[name])
		}
	}
	if (Result{ErrorClass: ErrClassDiscoveryFailed}).Validate() == nil {
		t.Error("discovery_failed is valid on a plain Result")
	}
}

func goodFinding() DiscoverFinding {
	return DiscoverFinding{Path: "/srv/app/app.env", Name: "API_KEY", Fingerprint: testFP, Len: 32}
}

func TestDecodeDiscoverResult(t *testing.T) {
	ok, _ := json.Marshal(DiscoverResult{OK: true, Findings: []DiscoverFinding{goodFinding()}})
	if _, err := DecodeDiscoverResult(ok); err != nil {
		t.Fatalf("good report: %v", err)
	}
	empty, _ := json.Marshal(DiscoverResult{OK: true, Findings: []DiscoverFinding{}})
	if _, err := DecodeDiscoverResult(empty); err != nil {
		t.Fatalf("empty report: %v", err)
	}
	failed, _ := json.Marshal(DiscoverResult{ErrorClass: ErrClassDiscoveryFailed, Findings: []DiscoverFinding{}})
	if _, err := DecodeDiscoverResult(failed); err != nil {
		t.Fatalf("failed report: %v", err)
	}
	f := `{"path":"/srv/a.env","name":"K","fingerprint":"` + testFP + `","len":3}`
	// Positive control for the required-field cases below: an explicit len 0
	// and a failed report with an explicit ok false are valid.
	for name, body := range map[string]string{
		"explicit len 0":    `{"ok":true,"findings":[{"path":"/srv/a.env","name":"K","fingerprint":"` + testFP + `","len":0}]}`,
		"explicit ok false": `{"ok":false,"error_class":"discovery_failed","findings":[]}`,
	} {
		if _, err := DecodeDiscoverResult([]byte(body)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, body := range map[string]string{
		"extra top key":       `{"ok":true,"findings":[],"value":"x"}`,
		"extra finding key":   `{"ok":true,"findings":[{"path":"/srv/a.env","name":"K","fingerprint":"` + testFP + `","len":3,"value":"x"}]}`,
		"case variant":        `{"OK":true,"findings":[]}`,
		"duplicate key":       `{"ok":true,"ok":true,"findings":[]}`,
		"finding case":        `{"ok":true,"findings":[{"Path":"/srv/a.env","name":"K","fingerprint":"` + testFP + `","len":3}]}`,
		"finding duplicate":   `{"ok":true,"findings":[{"path":"/srv/a.env","path":"/srv/b.env","name":"K","fingerprint":"` + testFP + `","len":3}]}`,
		"trailing":            `{"ok":true,"findings":[]} {}`,
		"ok with class":       `{"ok":true,"error_class":"internal","findings":[]}`,
		"failed with finding": `{"ok":false,"error_class":"discovery_failed","findings":[` + f + `]}`,
		"deploy-only class":   `{"ok":false,"error_class":"fingerprint_mismatch","findings":[]}`,
		"duplicate finding":   `{"ok":true,"findings":[` + f + `,` + strings.Replace(f, `"len":3`, `"len":4`, 1) + `]}`,
		"failed no class":     `{"ok":false,"findings":[]}`,
		"unknown class":       `{"ok":false,"error_class":"read_failed","findings":[]}`,
		"relative path":       `{"ok":true,"findings":[{"path":"a.env","name":"K","fingerprint":"` + testFP + `","len":3}]}`,
		"dotdot path":         `{"ok":true,"findings":[{"path":"/srv/../a.env","name":"K","fingerprint":"` + testFP + `","len":3}]}`,
		"bad fingerprint":     `{"ok":true,"findings":[{"path":"/srv/a.env","name":"K","fingerprint":"sha256:ab","len":3}]}`,
		"negative len":        `{"ok":true,"findings":[{"path":"/srv/a.env","name":"K","fingerprint":"` + testFP + `","len":-1}]}`,
		"bad name":            `{"ok":true,"findings":[{"path":"/srv/a.env","name":"K=v","fingerprint":"` + testFP + `","len":3}]}`,
		"missing findings":    `{"ok":true}`,
		"null findings":       `{"ok":true,"findings":null}`,
		"findings not array":  `{"ok":true,"findings":{}}`,
		"missing len":         `{"ok":true,"findings":[{"path":"/srv/a.env","name":"K","fingerprint":"` + testFP + `"}]}`,
		"null len":            `{"ok":true,"findings":[{"path":"/srv/a.env","name":"K","fingerprint":"` + testFP + `","len":null}]}`,
		"missing ok":          `{"error_class":"discovery_failed","findings":[]}`,
		"null ok":             `{"ok":null,"error_class":"discovery_failed","findings":[]}`,
	} {
		if _, err := DecodeDiscoverResult([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	many := make([]DiscoverFinding, MaxDiscoverFindings+1)
	for i := range many {
		many[i] = goodFinding()
	}
	b, _ := json.Marshal(DiscoverResult{OK: true, Findings: many})
	if _, err := DecodeDiscoverResult(b); err == nil {
		t.Error("oversize report accepted")
	}
}

// A finding built from a canary value carries its keyed fingerprint and
// length only: no encoding of the value appears anywhere in the wire form.
func TestDiscoverResultLeakCanary(t *testing.T) {
	c := canary.New()
	v := secret.New([]byte(c.Value(1)))
	defer v.Wipe()
	k, err := fingerprint.GenerateKey("disc1")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Wipe()
	fp, err := fingerprint.Compute(k, v)
	if err != nil {
		t.Fatal(err)
	}
	r := DiscoverResult{OK: true, Findings: []DiscoverFinding{{Path: "/srv/app.env", Name: "API_KEY", Fingerprint: fp, Len: len(c.Value(1))}}}
	b, _ := json.Marshal(r)
	if c.In(string(b)) || c.In(strings.Join([]string{r.Findings[0].Path, r.Findings[0].Name, r.Findings[0].Fingerprint}, "")) {
		t.Fatal("value escaped the discover report")
	}
	if _, err := DecodeDiscoverResult(b); err != nil {
		t.Fatal(err)
	}
	// Positive control: the detector sees the canary when it is present.
	if !c.In(`{"name":"` + c.Value(1) + `"}`) {
		t.Fatal("canary detector is blind")
	}
}

// Validate, Marshal and Decode must agree: a nil Findings marshals to
// findings:null, which the decoder refuses, so Validate must refuse it too.
func TestDiscoverResultNilFindingsConsistent(t *testing.T) {
	for name, r := range map[string]DiscoverResult{
		"success-nil":   {OK: true},
		"failure-nil":   {OK: false, ErrorClass: ErrClassDiscoveryFailed},
		"success-empty": {OK: true, Findings: []DiscoverFinding{}},
		"failure-empty": {OK: false, ErrorClass: ErrClassDiscoveryFailed, Findings: []DiscoverFinding{}},
	} {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		_, decErr := DecodeDiscoverResult(b)
		valErr := r.Validate()
		if (valErr == nil) != (decErr == nil) {
			t.Errorf("%s: validate=%v decode=%v disagree", name, valErr, decErr)
		}
		if strings.HasSuffix(name, "-nil") && valErr == nil {
			t.Errorf("%s: nil findings accepted", name)
		}
		if strings.HasSuffix(name, "-empty") && valErr != nil {
			t.Errorf("%s: empty findings refused: %v", name, valErr)
		}
	}
}
