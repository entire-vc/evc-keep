package scopedtransfer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

func validManifest() Manifest {
	in := validInventory()
	return Manifest{
		Version: ManifestVersion, ProfileVersion: ProfileVersion,
		TransferID: uuid.NewString(), OrgID: in.OrgID, WorkspaceID: in.WorkspaceID,
		SchemaVersion: SchemaVersion, MigrationSetID: MigrationSetID,
		RecipientID: uuid.NewString(), SnapshotID: uuid.NewString(),
		ClosureDigest: "sha256:" + strings.Repeat("a", 64), Tables: in.Tables,
	}
}

func encode(t *testing.T, m Manifest) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal("cannot encode fixture")
	}
	return raw
}

func TestManifestRoundTrip(t *testing.T) {
	want := validManifest()
	got, err := ParseManifest(encode(t, want))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("valid manifest did not round-trip")
	}
}

func TestManifestRejectsInvalid(t *testing.T) {
	valid := encode(t, validManifest())
	cases := map[string][]byte{
		"empty":            nil,
		"oversize":         append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), MaxManifestBytes)...),
		"trailing value":   append(append([]byte(nil), valid...), []byte(`{}`)...),
		"trailing garbage": append(append([]byte(nil), valid...), 'x'),
		"unknown field":    bytes.Replace(valid, []byte(`{"version"`), []byte(`{"extra":1,"version"`), 1),
		"duplicate field":  bytes.Replace(valid, []byte(`{"version":1`), []byte(`{"version":1,"version":1`), 1),
		"not an object":    []byte(`[]`),
	}
	mutate := map[string]func(*Manifest){
		"future version":      func(m *Manifest) { m.Version++ },
		"future profile":      func(m *Manifest) { m.ProfileVersion++ },
		"bad transfer id":     func(m *Manifest) { m.TransferID = "x" },
		"nil recipient":       func(m *Manifest) { m.RecipientID = uuid.Nil.String() },
		"bad snapshot id":     func(m *Manifest) { m.SnapshotID = "" },
		"same org workspace":  func(m *Manifest) { m.WorkspaceID = m.OrgID },
		"wrong schema":        func(m *Manifest) { m.SchemaVersion-- },
		"unpinned migrations": func(m *Manifest) { m.MigrationSetID = "sha256:" + strings.Repeat("0", 64) },
		"short digest":        func(m *Manifest) { m.ClosureDigest = "sha256:abc" },
		"uppercase digest":    func(m *Manifest) { m.ClosureDigest = "sha256:" + strings.Repeat("A", 64) },
		"missing table":       func(m *Manifest) { m.Tables = m.Tables[1:] },
		"unsupported state":   func(m *Manifest) { setManifestCount(m, "runners", 1) },
		"no organization":     func(m *Manifest) { setManifestCount(m, "organizations", 0) },
	}
	for name, f := range mutate {
		m := validManifest()
		f(&m)
		cases[name] = encode(t, m)
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := ParseManifest(raw)
			if !errors.Is(err, ErrManifest) || !reflect.DeepEqual(m, Manifest{}) {
				t.Fatal("invalid manifest not rejected with only ErrManifest and an empty value")
			}
		})
	}
}

func setManifestCount(m *Manifest, name string, rows int64) {
	for i := range m.Tables {
		if m.Tables[i].Name == name {
			m.Tables[i].Rows = rows
		}
	}
}

func TestManifestErrorDoesNotEchoInput(t *testing.T) {
	c := canary.New()
	if !c.In("positive control " + c.Value(1)) {
		t.Fatal("canary detector missed the positive control")
	}
	for name, f := range map[string]func(*Manifest){
		"org":       func(m *Manifest) { m.OrgID = c.Value(1) },
		"recipient": func(m *Manifest) { m.RecipientID = c.Value(1) },
		"digest":    func(m *Manifest) { m.ClosureDigest = c.Value(1) },
		"table":     func(m *Manifest) { m.Tables[0].Name = c.Value(1) },
		"migration": func(m *Manifest) { m.MigrationSetID = c.Value(1) },
	} {
		m := validManifest()
		f(&m)
		_, err := ParseManifest(encode(t, m))
		if err == nil {
			t.Fatalf("%s: invalid manifest accepted", name)
		}
		encoded, _ := json.Marshal(err)
		for _, out := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), string(encoded)} {
			if c.In(out) {
				t.Fatalf("%s: error exposes input", name)
			}
		}
	}
	// Unknown-field and malformed-JSON paths must not echo decoder text.
	raw := []byte(`{"` + c.Value(1) + `":1}`)
	if _, err := ParseManifest(raw); err == nil || c.In(err.Error()) {
		t.Fatal("decoder text leaked or input accepted")
	}
}
