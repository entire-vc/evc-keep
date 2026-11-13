package transferverify

import (
	"reflect"
	"testing"

	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/google/uuid"
)

// withField returns a copy of rows in which field of the first row of table is
// set to v, or false when the fixture holds no such row or field.
func withField(rows *store.TransferRows, table, field string, v uuid.UUID) (*store.TransferRows, bool) {
	cp := *rows
	rv := reflect.ValueOf(&cp).Elem().FieldByName(table)
	if rv.Kind() != reflect.Slice || rv.Len() == 0 {
		return nil, false
	}
	fresh := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
	reflect.Copy(fresh, rv)
	rv.Set(fresh)
	f := rv.Index(0).FieldByName(field)
	if !f.IsValid() || f.Type() != reflect.TypeOf(uuid.UUID{}) {
		return nil, false
	}
	f.Set(reflect.ValueOf(v))
	return &cp, true
}

// Every table with an organisation or mesh-workspace column is checked against
// it, and every foreign key that the closure follows is followed: moving one
// row's column to a foreign id must be refused, table by table.
func TestClosureChecksEveryTableColumn(t *testing.T) {
	rows, org := seededRows(t)
	other := uuid.New()
	rt := reflect.TypeOf(*rows)
	tested := map[string]int{}
	for i := 0; i < rt.NumField(); i++ {
		table := rt.Field(i).Name
		et := rt.Field(i).Type
		if et.Kind() != reflect.Slice || et.Elem().Kind() != reflect.Struct {
			continue
		}
		for _, col := range []string{"OrgID", "WorkspaceID"} {
			cp, ok := withField(rows, table, col, other)
			if !ok {
				continue
			}
			if err := Closure(cp, org); err == nil {
				t.Errorf("%s.%s moved to a foreign id was accepted", table, col)
			}
			tested[col]++
		}
	}
	for _, ref := range []struct{ table, col string }{
		{"Memberships", "UserID"}, {"AgentGrants", "AgentID"}, {"Projects", "WorkspaceID"},
		{"StoreBindings", "StoreID"}, {"Agents", "SponsorUserID"},
	} {
		cp, ok := withField(rows, ref.table, ref.col, other)
		if !ok {
			t.Errorf("fixture has no %s row to test %s", ref.table, ref.col)
			continue
		}
		if err := Closure(cp, org); err == nil {
			t.Errorf("%s.%s dangling reference was accepted", ref.table, ref.col)
		}
	}
	if tested["OrgID"] < 12 || tested["WorkspaceID"] < 5 {
		t.Errorf("positive control: too few tables exercised: %v", tested)
	}
}
