package catalog

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func requireMetadataRejection(t *testing.T, err error, c canary.Canary) {
	t.Helper()
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Class != apperr.ClassInvalidArgument {
		t.Fatal("metadata guard did not return invalid_argument")
	}
	if c.In(err.Error()) {
		t.Fatal("rejected metadata escaped through the error")
	}
}

func TestCreateRefMetadataValidation(t *testing.T) {
	f := newFixture(t)
	store := f.mustStore("safe store", tenancy.Org(f.org.ID))
	c := canary.New()
	if !c.In("rejected " + c.Value(0)) {
		t.Fatal("canary positive control failed")
	}
	for field, limit := range map[string]int{"name": 128, "description": 1024, "class": 64, "type": 64} {
		set := func(in *CreateRefInput, value string) {
			switch field {
			case "name":
				in.Name = value
			case "description":
				in.Description = value
			case "class":
				in.Class = value
			case "type":
				in.Type = value
			}
		}
		base := CreateRefInput{Org: f.org.ID, Scope: tenancy.Org(f.org.ID), StoreID: store.ID,
			Name: "safe-" + field, Class: "credential", Type: "generic", ProviderRef: "builtin://default/test"}
		// Rune limits must permit multibyte, printable text right at the boundary.
		valid := base
		set(&valid, strings.Repeat("界", limit))
		if _, err := f.cat.CreateRef(f.ctx, valid); err != nil {
			t.Fatal("valid metadata boundary rejected")
		}
		for shape, bad := range map[string]string{
			"utf8": "\xff", "surrogate": "\xed\xa0\x80", "esc": "\x1b[2J", "osc": "\x1b]0;x\x07", "c1": "\u009b",
			"del": "\x7f", "tab": "\t", "newline": "\n", "bidi": "\u202e", "isolate": "\u2066",
			"format": "\u200e", "private": "\ue000", "nbsp": "\u00a0", "line": "\u2028", "paragraph": "\u2029",
			"length": strings.Repeat("界", limit+1-utf8.RuneCountInString(c.Value(0))),
		} {
			t.Run(field+"/"+shape, func(t *testing.T) {
				in := base
				set(&in, c.Value(0)+bad)
				_, err := f.cat.CreateRef(f.ctx, in)
				requireMetadataRejection(t, err, c)
			})
		}
	}
	rows, err := f.cat.List(f.ctx, f.org.ID, tenancy.Org(f.org.ID))
	if err != nil || len(rows) != 4 {
		t.Fatal("rejected metadata was persisted")
	}
}

// Store and scope/principal names have separate SQL writers: no HTTP layer
// is involved, so these probes prove the shared write boundary is enforced.
func TestOtherMetadataWritersValidation(t *testing.T) {
	f := newFixture(t)
	ws := f.mustWorkspace("safe workspace")
	u := f.mustUser("sponsor")
	c := canary.New()
	writers := map[string]func(string) error{
		"store": func(v string) error {
			_, e := f.cat.CreateStore(f.ctx, f.org.ID, "vault", v, tenancy.Org(f.org.ID))
			return e
		},
		"organization": func(v string) error { _, e := f.rp.CreateOrganization(f.ctx, v, ""); return e },
		"workspace":    func(v string) error { _, e := f.rp.CreateWorkspace(f.ctx, f.org.ID, v); return e },
		"project":      func(v string) error { _, e := f.rp.CreateProject(f.ctx, f.org.ID, ws.ID, v); return e },
		"agent":        func(v string) error { _, e := f.rp.CreateAgent(f.ctx, f.org.ID, u.ID, v); return e },
		"service":      func(v string) error { _, e := f.rp.CreateService(f.ctx, f.org.ID, v, tenancy.Org(f.org.ID)); return e },
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			if err := write(strings.Repeat("界", 128)); err != nil {
				t.Fatal("valid name boundary rejected")
			}
			for _, bad := range []string{c.Value(0) + "\u202e", c.Value(0) + "\xff", c.Value(0) + strings.Repeat("界", 129-utf8.RuneCountInString(c.Value(0)))} {
				requireMetadataRejection(t, write(bad), c)
			}
		})
	}
}
