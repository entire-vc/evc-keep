package meshext

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A missing journal is an invalid argument, refused before opening a
// transaction or running a seal that commits on its own connection.
func TestBindingSettingsRequireJournalBeforeSideEffects(t *testing.T) {
	for _, path := range []string{"bind", "upgrade"} {
		for _, missing := range []string{"first", "later"} {
			t.Run(path+"/"+missing, func(t *testing.T) {
				// No database is needed to reject an invalid snapshot. A
				// database access here violates the prevalidation contract.
				r := NewRepo(nil)
				defer func() {
					if recover() != nil {
						t.Fatal("accessed the database before rejecting a missing journal")
					}
				}()
				settings := []Snapshot{{}}
				if missing == "later" {
					settings = append([]Snapshot{{Journal: func(context.Context, pgx.Tx, uuid.UUID, Settings) error {
						t.Fatal("journal ran before rejecting a later missing journal")
						return nil
					}}}, settings...)
				}
				seal := func(context.Context) error {
					t.Fatal("seal ran before rejecting a missing journal")
					return nil
				}
				var err error
				if path == "bind" {
					err = r.BindPending(context.Background(), uuid.New(), Pending{}, ModeExtension, seal, settings...)
				} else {
					err = r.UpgradeStore(context.Background(), uuid.New(), Pending{}, seal, settings...)
				}
				if !errors.Is(err, ErrNoSettingsJournal) {
					t.Fatalf("got %v, want ErrNoSettingsJournal", err)
				}
			})
		}
	}
}

func TestParseSettingsDistinguishesAbsentFromNull(t *testing.T) {
	if s, present, err := ParseSettings(nil); err != nil || present || s.ApprovalsViaMesh != nil {
		t.Fatal("an absent snapshot must leave the stored setting unchanged")
	}
	for _, raw := range []string{"null", " \n null\t"} {
		s, present, err := ParseSettings(json.RawMessage(raw))
		if !errors.Is(err, ErrInvalidSettings) || present || s.ApprovalsViaMesh != nil {
			t.Fatal("a present null snapshot must be rejected without a setting")
		}
	}
	if s, present, err := ParseSettings(json.RawMessage(`{}`)); err != nil || !present || s.ApprovalsViaMesh != nil {
		t.Fatal("an empty object must remain a valid snapshot selecting the default")
	}
}
