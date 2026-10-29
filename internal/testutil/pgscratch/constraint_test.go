package pgscratch

import (
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestDropConstraintOnlyOnScratchDatabase(t *testing.T) {
	base := os.Getenv("KEEP_DATABASE_URL")
	if base == "" {
		t.Skip("KEEP_DATABASE_URL not set — see CONTRIBUTING.md")
	}
	for _, tc := range []struct {
		name string
		dsn  func(t *testing.T) string
		want bool
	}{
		{"shared", func(t *testing.T) string { return DSN(t, base) }, false},
		{"scratch", func(t *testing.T) string { return New(t, nil) }, true},
		{"shared-scratch-name", func(t *testing.T) string { return New(t, nil) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each case creates its own database inside its own test, so a
			// slow CREATE DATABASE on a busy server is not summed across
			// cases before the first one starts.
			dsn := tc.dsn(t)
			if tc.name == "shared-scratch-name" {
				t.Setenv("KEEP_DATABASE_URL", dsn)
			}
			conn, err := pgx.Connect(Context(t), dsn)
			if err != nil {
				t.Fatal("open test connection failed")
			}
			t.Cleanup(func() { _ = conn.Close(Context(t)) })
			// TEMP makes even the shared-database negative control harmless.
			if _, err := conn.Exec(Context(t), `CREATE TEMP TABLE constraint_probe (id text CONSTRAINT id_shape CHECK (id = 'valid'))`); err != nil {
				t.Fatal("create constraint probe failed")
			}
			if _, err := conn.Exec(Context(t), `INSERT INTO constraint_probe VALUES ('valid')`); err != nil {
				t.Fatal("valid row was rejected")
			}
			if _, err := conn.Exec(Context(t), `INSERT INTO constraint_probe VALUES ('invalid')`); err == nil {
				t.Fatal("constraint did not reject invalid row before removal")
			}
			err = dropConstraint(Context(t), conn, "constraint_probe", "id_shape")
			if tc.want && err != nil {
				t.Fatal("scratch constraint removal failed")
			}
			if !tc.want && !errors.Is(err, errNotScratch) {
				t.Fatal("shared database constraint removal was not refused")
			}
			_, err = conn.Exec(Context(t), `INSERT INTO constraint_probe VALUES ('invalid')`)
			if (err == nil) != tc.want {
				t.Fatal("constraint state does not match scratch-only removal")
			}
		})
	}
}
