package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A database left at PostgreSQL's defaults writes a rejected row's data
// into the server log (DETAIL: Failing row contains ..., STATEMENT: ...).
// CheckLogSettings must reject it, and must reject a database that fixed
// only one of the two settings — terse alone still logs STATEMENT with any
// literal values in it.
func TestCheckLogSettings(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]string
		want     []string // settings expected in the mismatch list; empty = pass
	}{
		{"server defaults", nil, []string{"log_error_verbosity", "log_min_error_statement", "log_min_messages"}},
		{"terse only", map[string]string{"log_error_verbosity": "terse"}, []string{"log_min_error_statement", "log_min_messages"}},
		{"statement threshold only", map[string]string{"log_min_error_statement": "panic"}, []string{"log_error_verbosity", "log_min_messages"}},
		{"both set", goodSettings(), nil},
		// PostgreSQL's own defaults already satisfy log_statement=none and
		// the three duration/sample settings at -1/-1/0, so a case that
		// only sets the two original settings (above) never exercises
		// these — each needs an explicit bad value to prove it's actually
		// enforced, isolated from the others by starting from a fully
		// correct baseline.
		{"log_statement enabled", withBadSetting("log_statement", "all"), []string{"log_statement"}},
		{"log_statement mod", withBadSetting("log_statement", "mod"), []string{"log_statement"}},
		{"log_statement ddl is allowed", withBadSetting("log_statement", "ddl"), nil},
		{"log_min_duration_statement enabled", withBadSetting("log_min_duration_statement", "0"), []string{"log_min_duration_statement"}},
		{"log_min_duration_sample enabled", withBadSetting("log_min_duration_sample", "0"), []string{"log_min_duration_sample"}},
		{"log_transaction_sample_rate enabled", withBadSetting("log_transaction_sample_rate", "1"), []string{"log_transaction_sample_rate"}},
		// keep-leak-reviewer, fourth round: debug_print_plan and its
		// siblings are "user"-context and write the query tree, bound
		// parameters included, to the log regardless of the settings
		// above — log_min_messages raised high enough is the real
		// defense, since it suppresses their LOG-severity output no
		// matter who turns debug_print_* on. PostgreSQL's default
		// (warning) fails this like every other setting above.
		{"log_min_messages warning", withBadSetting("log_min_messages", "warning"), []string{"log_min_messages"}},
		{"log_min_messages panic is allowed", withBadSetting("log_min_messages", "panic"), nil},
		// keep-leak-reviewer, fifth round: error is the value closest to
		// the allowed set, and the one is_log_level_output actually treats
		// differently from warning — LOG-severity messages (debug_print_*
		// included) still reach the server log at every threshold up to
		// and including error, only fatal and panic suppress them. A
		// mutant widening AllowedLogMinMessages to admit error passed
		// every case above, since only warning (PostgreSQL's own default)
		// was ever tried as a bad value.
		{"log_min_messages error", withBadSetting("log_min_messages", "error"), []string{"log_min_messages"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := pgxpool.New(pgscratch.Context(t), pgscratch.New(t, tc.settings))
			if err != nil {
				t.Fatal("open scratch pool failed") // the error text can repeat the DSN
			}
			t.Cleanup(pool.Close)
			err = CheckLogSettings(pgscratch.Context(t), pool)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("CheckLogSettings on a correctly configured database: %v", err)
				}
				return
			}
			var lse *LogSettingsError
			if !errors.As(err, &lse) {
				t.Fatalf("CheckLogSettings = %v, want *LogSettingsError naming %v", err, tc.want)
			}
			if len(lse.Mismatches) != len(tc.want) {
				t.Fatalf("mismatches = %v, want exactly %v", lse.Mismatches, tc.want)
			}
			for _, name := range tc.want {
				if _, ok := lse.Mismatches[name]; !ok {
					t.Fatalf("mismatches = %v, missing %s", lse.Mismatches, name)
				}
			}
		})
	}

	// keep-leak-reviewer, fifth round: LogSettingsError.Error() must
	// actually name the values log_min_messages is allowed to have — a
	// mutant dropping wantText's logMinMessagesSetting case passed every
	// case above, since none of them looked at the error text, only at
	// Mismatches. An empty "want" clause isn't a leak, but it is a
	// misleading operator-facing message this test now catches.
	t.Run("log_min_messages mismatch names the allowed values", func(t *testing.T) {
		pool, err := pgxpool.New(pgscratch.Context(t), pgscratch.New(t, withBadSetting("log_min_messages", "warning")))
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)
		err = CheckLogSettings(pgscratch.Context(t), pool)
		if err == nil || !strings.Contains(err.Error(), "want fatal or panic") {
			t.Fatalf("CheckLogSettings error = %v, want text naming the allowed log_min_messages values", err)
		}
	})

	// keep-leak-reviewer, sixth round: enumerating one bad value at a time
	// (warning, then error) only proves those specific values are
	// rejected — log_min_messages has its own PostgreSQL enum (on 17:
	// debug5..debug1, info, notice, warning, error, log, fatal, panic) and
	// is_log_level_output prints every one of them below fatal at LOG
	// severity or louder, debug_print_*'s output included. log leaked
	// exactly like error, live-verified by the reviewer, and stayed
	// uncaught because only error was ever added as a case. Read
	// PostgreSQL's own enum for the setting from pg_settings and check
	// every value it contains — not just the ones this file happens to
	// name — against safeLogMinMessages, a literal kept independent of
	// AllowedLogMinMessages itself: a mutation that widens the production
	// list must not also widen what this test calls safe, or the test
	// would pass right along with the mutant.
	t.Run("log_min_messages: every value postgres allows is checked against a fixed safe set", func(t *testing.T) {
		safeLogMinMessages := []string{"fatal", "panic"}

		adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.New(t, nil))
		if err != nil {
			t.Fatal("open admin pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(adminPool.Close)
		var enumvals []string
		if err := adminPool.QueryRow(pgscratch.Context(t),
			"SELECT enumvals FROM pg_settings WHERE name = 'log_min_messages'").Scan(&enumvals); err != nil {
			t.Fatalf("read log_min_messages enumvals failed (%s)", sqlStateOf(err))
		}
		if len(enumvals) == 0 {
			t.Fatal("log_min_messages enumvals came back empty; this test proves nothing")
		}
		// keep-leak-reviewer, seventh round: a non-empty list alone doesn't
		// prove PostgreSQL's own enum still contains the two values this
		// test exists to catch — a future PostgreSQL version narrowing or
		// renaming log_min_messages' enum could shrink coverage silently.
		for _, want := range []string{"log", "error"} {
			if !slices.Contains(enumvals, want) {
				t.Fatalf("log_min_messages enumvals = %v, missing %s — this test no longer covers the value it exists for", enumvals, want)
			}
		}

		for _, val := range enumvals {
			safe := slices.Contains(safeLogMinMessages, val)
			t.Run(val, func(t *testing.T) {
				pool, err := pgxpool.New(pgscratch.Context(t), pgscratch.New(t, withBadSetting("log_min_messages", val)))
				if err != nil {
					t.Fatal("open scratch pool failed") // the error text can repeat the DSN
				}
				t.Cleanup(pool.Close)
				err = CheckLogSettings(pgscratch.Context(t), pool)
				if safe {
					if err != nil {
						t.Fatalf("CheckLogSettings with log_min_messages=%s = %v, want nil", val, err)
					}
					return
				}
				var lse *LogSettingsError
				if !errors.As(err, &lse) {
					t.Fatalf("CheckLogSettings with log_min_messages=%s = %v, want *LogSettingsError", val, err)
				}
				got, ok := lse.Mismatches["log_min_messages"]
				if !ok {
					t.Fatalf("mismatches = %v, missing log_min_messages for %s", lse.Mismatches, val)
				}
				if got != val {
					t.Fatalf("mismatches[log_min_messages] = %q, want %q — CheckLogSettings may not have read the value this test actually set", got, val)
				}
			})
		}
	})
}

// goodSettings returns a database configuration that satisfies every
// setting CheckLogSettings checks: RequiredLogSettings verbatim, plus
// log_statement and log_min_messages set to one of their allowed values
// each — PostgreSQL's own defaults satisfy neither.
func goodSettings() map[string]string {
	settings := map[string]string{
		logStatementSetting:   "'none'",
		logMinMessagesSetting: "fatal",
	}
	for k, v := range RequiredLogSettings {
		settings[k] = v
	}
	return settings
}

// withBadSetting starts from goodSettings, then overrides exactly one
// setting to a bad value — isolating that one setting's enforcement from
// the rest.
//
// log_statement's values are quoted: pgscratch.New writes a setting's value
// into SQL unquoted, and ALL is a reserved SQL keyword, so
// "SET log_statement = all" is itself a syntax error.
func withBadSetting(name, value string) map[string]string {
	settings := goodSettings()
	if name == logStatementSetting {
		value = "'" + value + "'"
	}
	settings[name] = value
	return settings
}

// auto_explain writes a statement's execution plan — bound parameter
// values inlined as literals by the planner — to the server log once its
// own log_min_duration threshold is crossed, independent of every
// statement-logging setting [TestCheckLogSettings] exercises: it hooks the
// planner/executor directly, not PostgreSQL's own statement-logging path.
// log_min_messages at 'fatal'/'panic', which [TestCheckLogSettings] also
// requires, is still the first barrier (auto_explain's own output is
// filtered by that same severity); this guard is the second, independent
// of whether that first one ever gets loosened. Verified live against a
// server with shared_preload_libraries=auto_explain (see
// internal/store/loghygiene.go's doc for the exact commands and the
// captured log line) before writing this test: with the guard commented
// out and log_min_messages at a normal (non-panic/fatal) level,
// CheckLogSettings passed a database where a canary bind parameter was
// landing in the server log's Filter line on every matching query.
func TestCheckLogSettings_AutoExplain(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]string
		want     []string
	}{
		{"disabled (-1), same as its own default", goodSettings(), nil},
		{"enabled at threshold 0", withBadSetting("auto_explain.log_min_duration", "0"), []string{"auto_explain.log_min_duration"}},
		{"enabled at a high threshold", withBadSetting("auto_explain.log_min_duration", "60000"), []string{"auto_explain.log_min_duration"}},
		// Pins the measurement in loghygiene.go's doc: log_parameter_max_length
		// alone does not close the leak, so a database that "fixed" only that
		// setting must still be rejected for log_min_duration.
		{
			"log_parameter_max_length=0 does not excuse log_min_duration=0",
			withSettings(goodSettings(), map[string]string{
				"auto_explain.log_min_duration":         "0",
				"auto_explain.log_parameter_max_length": "0",
			}),
			[]string{"auto_explain.log_min_duration"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := pgxpool.New(pgscratch.Context(t), pgscratch.New(t, tc.settings))
			if err != nil {
				t.Fatal("open scratch pool failed") // the error text can repeat the DSN
			}
			t.Cleanup(pool.Close)
			err = CheckLogSettings(pgscratch.Context(t), pool)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("CheckLogSettings on a database with auto_explain disabled: %v", err)
				}
				return
			}
			var lse *LogSettingsError
			if !errors.As(err, &lse) {
				t.Fatalf("CheckLogSettings = %v, want *LogSettingsError naming %v", err, tc.want)
			}
			for _, name := range tc.want {
				if _, ok := lse.Mismatches[name]; !ok {
					t.Fatalf("mismatches = %v, missing %s", lse.Mismatches, name)
				}
			}
		})
	}

	t.Run("mismatch names the required value", func(t *testing.T) {
		pool, err := pgxpool.New(pgscratch.Context(t), pgscratch.New(t, withBadSetting("auto_explain.log_min_duration", "0")))
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)
		err = CheckLogSettings(pgscratch.Context(t), pool)
		if err == nil || !strings.Contains(err.Error(), "want -1 or unset") {
			t.Fatalf("CheckLogSettings error = %v, want text naming the required auto_explain.log_min_duration value", err)
		}
	})
}

// A setting name PostgreSQL has never heard of must read as "not loaded",
// not as an error — the path a real deployment without
// shared_preload_libraries=auto_explain takes for every
// auto_explain.* GUC. This is independent of whether the server this suite
// runs against happens to preload auto_explain (the CI service now does,
// so that specific extension's own settings can't exercise this path
// directly any more).
func TestReadNullableLogSetting_UnknownSettingIsNotAnError(t *testing.T) {
	pool, err := pgxpool.New(pgscratch.Context(t), pgscratch.New(t, nil))
	if err != nil {
		t.Fatal("open scratch pool failed") // the error text can repeat the DSN
	}
	t.Cleanup(pool.Close)
	_, ok, err := readNullableLogSetting(pgscratch.Context(t), pool, "keep_test_definitely_unknown_setting_xyz")
	if err != nil {
		t.Fatalf("readNullableLogSetting on an unknown setting name = %v, want ok=false, err=nil", err)
	}
	if ok {
		t.Fatal("readNullableLogSetting reported an unknown setting as present")
	}
}

// withSettings starts from base, then overrides or adds every key in
// extra — for a test case that needs more than the one override
// withBadSetting allows.
func withSettings(base map[string]string, extra map[string]string) map[string]string {
	settings := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		settings[k] = v
	}
	for k, v := range extra {
		settings[k] = v
	}
	return settings
}

// A role left at PostgreSQL's default (superuser, in the CI postgres
// service — see internal/testutil/pgscratch's doc) can undo everything
// CheckLogSettings just verified with a plain SET in its own session.
// CheckNotSuperuser must refuse it, and must accept a role created without
// superuser rights on an otherwise identically configured database.
func TestCheckNotSuperuser(t *testing.T) {
	dsn := pgscratch.New(t, RequiredLogSettings)

	t.Run("superuser refused", func(t *testing.T) {
		pool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		err = CheckNotSuperuser(pgscratch.Context(t), pool)
		var se *SuperuserError
		if !errors.As(err, &se) {
			t.Fatalf("CheckNotSuperuser on the superuser scratch role = %v, want *SuperuserError", err)
		}
	})

	t.Run("non-superuser accepted", func(t *testing.T) {
		roleDSN := pgscratch.NewRole(t, dsn)
		pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		if err := CheckNotSuperuser(pgscratch.Context(t), pool); err != nil {
			t.Fatalf("CheckNotSuperuser on a non-superuser role: %v", err)
		}
	})

	// A superuser can connect with a "role" parameter in the DSN (libpq and
	// pgx both forward an unrecognized connection parameter as a run-time
	// GUC in the startup packet — the same effect as SET ROLE right after
	// connecting) to make current_user report the unprivileged scratch
	// role for the rest of the session. session_user stays the superuser
	// that opened the connection, fixed for its whole life, and RESET ROLE
	// always restores superuser privileges. Red without CheckNotSuperuser
	// checking session_user instead of current_user: this case would pass
	// straight through.
	t.Run("superuser refused even with role parameter set", func(t *testing.T) {
		roleDSN := pgscratch.NewRole(t, dsn)
		ru, err := url.Parse(roleDSN)
		if err != nil {
			t.Fatal("scratch role DSN is not a URL")
		}
		roleName := ru.User.Username()

		au, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("scratch database DSN is not a URL")
		}
		q := au.Query()
		q.Set("role", roleName)
		au.RawQuery = q.Encode()

		pool, err := pgxpool.New(pgscratch.Context(t), au.String())
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		err = CheckNotSuperuser(pgscratch.Context(t), pool)
		var se *SuperuserError
		if !errors.As(err, &se) {
			t.Fatalf("CheckNotSuperuser on a superuser connection with role= set = %v, want *SuperuserError", err)
		}
	})

	// PostgreSQL 15+'s GRANT SET ON PARAMETER lets a genuinely
	// non-superuser role change an individual GUC without ever holding
	// rolsuper — same effect as a superuser session running a plain SET,
	// and not something the rolsuper check above catches. Red without
	// CheckNotSuperuser's has_parameter_privilege loop.
	//
	// keep-leak-reviewer, fifth round: table-driven over every setting the
	// loop is supposed to name, not just log_statement — a mutant dropping
	// logMinMessagesSetting from the two constants appended directly, or
	// removing the "for name := range RequiredLogSettings" loop that adds
	// the rest, passed every test above this round, since none of them
	// ever granted SET ON PARAMETER on anything but log_statement. This
	// list is its own independent literal, not RequiredLogSettings itself
	// plus the two constants — a mutation shrinking what the production
	// code checks doesn't also shrink what this test tries.
	for _, setting := range []string{
		"log_statement",
		"log_min_messages",
		"log_error_verbosity",
		"log_min_error_statement",
		"log_min_duration_statement",
		"log_min_duration_sample",
		"log_transaction_sample_rate",
	} {
		t.Run(setting+" parameter privilege refused, revoke restores pass", func(t *testing.T) {
			roleDSN := pgscratch.NewRole(t, dsn)
			ru, err := url.Parse(roleDSN)
			if err != nil {
				t.Fatal("scratch role DSN is not a URL")
			}
			roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

			adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
			if err != nil {
				t.Fatal("open admin pool failed") // the error text can repeat the DSN
			}
			t.Cleanup(adminPool.Close)
			settingIdent := pgx.Identifier{setting}.Sanitize()
			if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT SET ON PARAMETER "+settingIdent+" TO "+roleIdent); err != nil {
				t.Fatalf("grant SET ON PARAMETER failed (%s)", sqlStateOf(err))
			}

			pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
			if err != nil {
				t.Fatal("open scratch pool failed") // the error text can repeat the DSN
			}
			t.Cleanup(pool.Close)

			err = CheckNotSuperuser(pgscratch.Context(t), pool)
			var ppe *ParameterPrivilegeError
			if !errors.As(err, &ppe) {
				t.Fatalf("CheckNotSuperuser on a role granted SET ON PARAMETER %s = %v, want *ParameterPrivilegeError", setting, err)
			}
			if ppe.Setting != setting {
				t.Errorf("ParameterPrivilegeError.Setting = %q, want %s", ppe.Setting, setting)
			}

			if _, err := adminPool.Exec(pgscratch.Context(t), "REVOKE SET ON PARAMETER "+settingIdent+" FROM "+roleIdent); err != nil {
				t.Fatalf("revoke SET ON PARAMETER failed (%s)", sqlStateOf(err))
			}
			if err := CheckNotSuperuser(pgscratch.Context(t), pool); err != nil {
				t.Fatalf("CheckNotSuperuser after revoking SET ON PARAMETER %s: %v", setting, err)
			}
		})
	}

	// keep-leak-reviewer, third round: ALTER SYSTEM ON PARAMETER (PostgreSQL
	// 15+) is a separate grant from SET ON PARAMETER — it lets the role
	// change postgresql.conf itself rather than the running session, which
	// only matters to an operator using ALTER SYSTEM instead of ALTER
	// DATABASE for these settings, and only takes effect after the next
	// reload, but it is the same kind of undo and gets the same check.
	t.Run("alter system privilege refused", func(t *testing.T) {
		roleDSN := pgscratch.NewRole(t, dsn)
		ru, err := url.Parse(roleDSN)
		if err != nil {
			t.Fatal("scratch role DSN is not a URL")
		}
		roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

		adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
		if err != nil {
			t.Fatal("open admin pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(adminPool.Close)
		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT ALTER SYSTEM ON PARAMETER log_statement TO "+roleIdent); err != nil {
			t.Fatalf("grant ALTER SYSTEM ON PARAMETER failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE ALTER SYSTEM ON PARAMETER log_statement FROM "+roleIdent)
		})

		pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		err = CheckNotSuperuser(pgscratch.Context(t), pool)
		var ppe *ParameterPrivilegeError
		if !errors.As(err, &ppe) {
			t.Fatalf("CheckNotSuperuser on a role granted ALTER SYSTEM ON PARAMETER log_statement = %v, want *ParameterPrivilegeError", err)
		}
	})

	// A non-superuser role that is simply a member of a superuser role (no
	// rolsuper of its own) can still SET ROLE into it and act as superuser
	// for the rest of the session — undoing everything CheckLogSettings
	// verified just as directly as holding rolsuper itself. Checking only
	// session_user's own pg_roles row misses this; CheckNotSuperuser must
	// follow every role reachable via SET ROLE (pg_has_role(..., 'SET')).
	t.Run("superuser role membership refused", func(t *testing.T) {
		roleDSN := pgscratch.NewRole(t, dsn)
		ru, err := url.Parse(roleDSN)
		if err != nil {
			t.Fatal("scratch role DSN is not a URL")
		}
		roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

		adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
		if err != nil {
			t.Fatal("open admin pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(adminPool.Close)
		var adminUser string
		if err := adminPool.QueryRow(pgscratch.Context(t), "SELECT current_user").Scan(&adminUser); err != nil {
			t.Fatalf("read admin role name failed (%s)", sqlStateOf(err))
		}
		adminIdent := pgx.Identifier{adminUser}.Sanitize()

		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT "+adminIdent+" TO "+roleIdent); err != nil {
			t.Fatalf("grant superuser role membership failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE "+adminIdent+" FROM "+roleIdent)
		})

		pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		err = CheckNotSuperuser(pgscratch.Context(t), pool)
		var se *SuperuserError
		if !errors.As(err, &se) {
			t.Fatalf("CheckNotSuperuser on a role granted membership in the superuser role = %v, want *SuperuserError", err)
		}
	})

	// Same reachability gap, for parameter privilege: a role can be granted
	// SET ON PARAMETER, and a second role can reach it only through SET
	// ROLE, not through privilege inheritance — the membership below is
	// granted WITH INHERIT FALSE on purpose. has_parameter_privilege
	// already resolves a plain (inherited) membership on its own, verified
	// live against keep-goku-pg before writing this test: with INHERIT
	// TRUE, has_parameter_privilege(session_user, ...) alone already
	// returns true for the member role, no SET ROLE traversal needed. Only
	// NOINHERIT exposes the gap this test guards: the grant never applies
	// to the member role until it actually runs SET ROLE, which
	// has_parameter_privilege(session_user, ...) alone can't see coming.
	t.Run("parameter privilege via reachable role refused", func(t *testing.T) {
		roleDSN := pgscratch.NewRole(t, dsn)
		ru, err := url.Parse(roleDSN)
		if err != nil {
			t.Fatal("scratch role DSN is not a URL")
		}
		roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

		adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
		if err != nil {
			t.Fatal("open admin pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(adminPool.Close)

		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		holderIdent := pgx.Identifier{"keep_scratch_holder_" + hex.EncodeToString(b)}.Sanitize()
		if _, err := adminPool.Exec(pgscratch.Context(t), "CREATE ROLE "+holderIdent+" NOLOGIN NOSUPERUSER"); err != nil {
			t.Fatalf("create holder role failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "DROP ROLE IF EXISTS "+holderIdent)
		})
		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT SET ON PARAMETER log_statement TO "+holderIdent); err != nil {
			t.Fatalf("grant SET ON PARAMETER to holder role failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			// DROP ROLE on holderIdent (above) needs this revoked first:
			// a role holding a parameter grant can't be dropped while it
			// still holds it, same as DROP OWNED BY for table/schema
			// privileges.
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE SET ON PARAMETER log_statement FROM "+holderIdent)
		})
		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT "+holderIdent+" TO "+roleIdent+" WITH INHERIT FALSE"); err != nil {
			t.Fatalf("grant holder role membership failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE "+holderIdent+" FROM "+roleIdent)
		})

		pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		err = CheckNotSuperuser(pgscratch.Context(t), pool)
		var ppe *ParameterPrivilegeError
		if !errors.As(err, &ppe) {
			t.Fatalf("CheckNotSuperuser on a role reaching SET ON PARAMETER via membership = %v, want *ParameterPrivilegeError", err)
		}
	})

	// keep-leak-reviewer, third round: a membership granted WITH ADMIN
	// TRUE, INHERIT FALSE, SET FALSE is invisible to SET ROLE — the member
	// can neither inherit the target's privileges nor switch into it
	// directly — but ADMIN OPTION lets the member re-run the same GRANT
	// itself, adding WITH SET TRUE, and then SET ROLE straight through.
	// The check must follow every pg_auth_members edge, not just ones
	// usable right now, or this one extra self-GRANT defeats it.
	t.Run("parameter privilege reachable only via admin option refused", func(t *testing.T) {
		roleDSN := pgscratch.NewRole(t, dsn)
		ru, err := url.Parse(roleDSN)
		if err != nil {
			t.Fatal("scratch role DSN is not a URL")
		}
		roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

		adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
		if err != nil {
			t.Fatal("open admin pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(adminPool.Close)

		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		holderIdent := pgx.Identifier{"keep_scratch_holder_" + hex.EncodeToString(b)}.Sanitize()
		if _, err := adminPool.Exec(pgscratch.Context(t), "CREATE ROLE "+holderIdent+" NOLOGIN NOSUPERUSER"); err != nil {
			t.Fatalf("create holder role failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "DROP ROLE IF EXISTS "+holderIdent)
		})
		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT SET ON PARAMETER log_statement TO "+holderIdent); err != nil {
			t.Fatalf("grant SET ON PARAMETER to holder role failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE SET ON PARAMETER log_statement FROM "+holderIdent)
		})
		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT "+holderIdent+" TO "+roleIdent+" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"); err != nil {
			t.Fatalf("grant holder role admin option failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE "+holderIdent+" FROM "+roleIdent)
		})

		pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		err = CheckNotSuperuser(pgscratch.Context(t), pool)
		var ppe *ParameterPrivilegeError
		if !errors.As(err, &ppe) {
			t.Fatalf("CheckNotSuperuser on a role reaching SET ON PARAMETER only via ADMIN OPTION = %v, want *ParameterPrivilegeError", err)
		}
	})

	// keep-leak-reviewer, third round: pg_execute_server_program lets a
	// role run an arbitrary OS program as the server's own process user —
	// including a plain psql back into the same database as an admin
	// connection — without rolsuper ever being set on any role it can
	// reach. pg_write_server_files is the same gap through writing files
	// the server can later be made to read or execute.
	//
	// keep-leak-reviewer, fourth round: table-driven over both built-in
	// roles, not just pg_execute_server_program — a mutant that drops
	// only pg_write_server_files from the check stayed green when only
	// the first role was ever exercised by a test. Also now expects
	// *AdminEquivalentRoleError, not *SuperuserError: an operator reading
	// the error should be able to tell SUPERUSER from a built-in role
	// membership, since they're revoked differently.
	for _, builtin := range []string{"pg_execute_server_program", "pg_write_server_files"} {
		t.Run(builtin+" membership refused", func(t *testing.T) {
			roleDSN := pgscratch.NewRole(t, dsn)
			ru, err := url.Parse(roleDSN)
			if err != nil {
				t.Fatal("scratch role DSN is not a URL")
			}
			roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

			adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
			if err != nil {
				t.Fatal("open admin pool failed") // the error text can repeat the DSN
			}
			t.Cleanup(adminPool.Close)

			builtinIdent := pgx.Identifier{builtin}.Sanitize()
			if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT "+builtinIdent+" TO "+roleIdent); err != nil {
				t.Fatalf("grant %s failed (%s)", builtin, sqlStateOf(err))
			}
			t.Cleanup(func() {
				_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE "+builtinIdent+" FROM "+roleIdent)
			})

			pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
			if err != nil {
				t.Fatal("open scratch pool failed") // the error text can repeat the DSN
			}
			t.Cleanup(pool.Close)

			err = CheckNotSuperuser(pgscratch.Context(t), pool)
			var ae *AdminEquivalentRoleError
			if !errors.As(err, &ae) {
				t.Fatalf("CheckNotSuperuser on a role granted %s = %v, want *AdminEquivalentRoleError", builtin, err)
			}
		})
	}

	// lo_export and either lo_import overload write or read an arbitrary
	// file as the server's own OS user when EXECUTE is granted directly —
	// a separate ACL from pg_execute_server_program/pg_write_server_files
	// membership entirely, live-reproduced: a role holding neither built-in
	// role, granted only EXECUTE on lo_export, passed CheckNotSuperuser and
	// then wrote an arbitrary file as the postgres OS user.
	for _, signature := range []string{"lo_export(oid,text)", "lo_import(text)", "lo_import(text,oid)"} {
		t.Run(signature+" EXECUTE grant refused, revoke restores pass", func(t *testing.T) {
			roleDSN := pgscratch.NewRole(t, dsn)
			ru, err := url.Parse(roleDSN)
			if err != nil {
				t.Fatal("scratch role DSN is not a URL")
			}
			roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

			adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
			if err != nil {
				t.Fatal("open admin pool failed") // the error text can repeat the DSN
			}
			t.Cleanup(adminPool.Close)

			if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT EXECUTE ON FUNCTION "+signature+" TO "+roleIdent); err != nil {
				t.Fatalf("grant execute on %s failed (%s)", signature, sqlStateOf(err))
			}
			t.Cleanup(func() {
				_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE EXECUTE ON FUNCTION "+signature+" FROM "+roleIdent)
			})

			pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
			if err != nil {
				t.Fatal("open scratch pool failed") // the error text can repeat the DSN
			}
			t.Cleanup(pool.Close)

			err = CheckNotSuperuser(pgscratch.Context(t), pool)
			var ae *AdminEquivalentRoleError
			if !errors.As(err, &ae) {
				t.Fatalf("CheckNotSuperuser on a role granted EXECUTE on %s = %v, want *AdminEquivalentRoleError", signature, err)
			}

			if _, err := adminPool.Exec(pgscratch.Context(t), "REVOKE EXECUTE ON FUNCTION "+signature+" FROM "+roleIdent); err != nil {
				t.Fatalf("revoke execute on %s failed (%s)", signature, sqlStateOf(err))
			}
			if err := CheckNotSuperuser(pgscratch.Context(t), pool); err != nil {
				t.Fatalf("CheckNotSuperuser after revoking EXECUTE on %s: %v", signature, err)
			}
		})
	}

	// Same DO-NOT-SHIP round: a foreign server's user mapping can name any
	// role at all, including this database's own superuser — a role this
	// check has no way to inspect, since the mapped role may live on a
	// different server entirely — so USAGE on a foreign server is refused
	// outright rather than trying to classify a mapping as safe.
	// keep-leak-reviewer reproduced the related dblink_exec path live;
	// this test exercises the USAGE grant itself, on postgres_fdw, the
	// wrapper this database actually has installed.
	t.Run("foreign server USAGE grant refused, revoke restores pass", func(t *testing.T) {
		roleDSN := pgscratch.NewRole(t, dsn)
		ru, err := url.Parse(roleDSN)
		if err != nil {
			t.Fatal("scratch role DSN is not a URL")
		}
		roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

		adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
		if err != nil {
			t.Fatal("open admin pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(adminPool.Close)

		if _, err := adminPool.Exec(pgscratch.Context(t), "CREATE EXTENSION IF NOT EXISTS postgres_fdw"); err != nil {
			t.Fatalf("create postgres_fdw extension failed (%s)", sqlStateOf(err))
		}

		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		serverIdent := pgx.Identifier{"keep_scratch_srv_" + hex.EncodeToString(b)}.Sanitize()
		if _, err := adminPool.Exec(pgscratch.Context(t), "CREATE SERVER "+serverIdent+" FOREIGN DATA WRAPPER postgres_fdw"); err != nil {
			t.Fatalf("create foreign server failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "DROP SERVER IF EXISTS "+serverIdent)
		})

		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT USAGE ON FOREIGN SERVER "+serverIdent+" TO "+roleIdent); err != nil {
			t.Fatalf("grant usage on foreign server failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE USAGE ON FOREIGN SERVER "+serverIdent+" FROM "+roleIdent)
		})

		pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		err = CheckNotSuperuser(pgscratch.Context(t), pool)
		var ae *AdminEquivalentRoleError
		if !errors.As(err, &ae) {
			t.Fatalf("CheckNotSuperuser on a role granted USAGE on a foreign server = %v, want *AdminEquivalentRoleError", err)
		}

		if _, err := adminPool.Exec(pgscratch.Context(t), "REVOKE USAGE ON FOREIGN SERVER "+serverIdent+" FROM "+roleIdent); err != nil {
			t.Fatalf("revoke usage on foreign server failed (%s)", sqlStateOf(err))
		}
		if err := CheckNotSuperuser(pgscratch.Context(t), pool); err != nil {
			t.Fatalf("CheckNotSuperuser after revoking usage on foreign server: %v", err)
		}
	})

	// keep-leak-reviewer, fourth round: reachableRolesCTE's recursive term
	// must actually chain — a mutant that restricts every recursive step
	// to combine only with session_user's own base row (so it still finds
	// direct members, but never a member of a member) passed every
	// existing test here, since none of them chained more than one hop.
	// role -> mid -> a superuser role, two hops deep, is red only if the
	// recursion genuinely walks pg_auth_members transitively.
	t.Run("superuser reachable through two-hop role chain refused", func(t *testing.T) {
		roleDSN := pgscratch.NewRole(t, dsn)
		ru, err := url.Parse(roleDSN)
		if err != nil {
			t.Fatal("scratch role DSN is not a URL")
		}
		roleIdent := pgx.Identifier{ru.User.Username()}.Sanitize()

		adminPool, err := pgxpool.New(pgscratch.Context(t), pgscratch.DSN(t, dsn))
		if err != nil {
			t.Fatal("open admin pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(adminPool.Close)
		var adminUser string
		if err := adminPool.QueryRow(pgscratch.Context(t), "SELECT current_user").Scan(&adminUser); err != nil {
			t.Fatalf("read admin role name failed (%s)", sqlStateOf(err))
		}
		adminIdent := pgx.Identifier{adminUser}.Sanitize()

		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		midIdent := pgx.Identifier{"keep_scratch_mid_" + hex.EncodeToString(b)}.Sanitize()
		if _, err := adminPool.Exec(pgscratch.Context(t), "CREATE ROLE "+midIdent+" NOLOGIN NOSUPERUSER"); err != nil {
			t.Fatalf("create mid role failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "DROP ROLE IF EXISTS "+midIdent)
		})
		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT "+adminIdent+" TO "+midIdent); err != nil {
			t.Fatalf("grant superuser role to mid role failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE "+adminIdent+" FROM "+midIdent)
		})
		if _, err := adminPool.Exec(pgscratch.Context(t), "GRANT "+midIdent+" TO "+roleIdent); err != nil {
			t.Fatalf("grant mid role membership failed (%s)", sqlStateOf(err))
		}
		t.Cleanup(func() {
			_, _ = adminPool.Exec(pgscratch.Context(t), "REVOKE "+midIdent+" FROM "+roleIdent)
		})

		pool, err := pgxpool.New(pgscratch.Context(t), roleDSN)
		if err != nil {
			t.Fatal("open scratch pool failed") // the error text can repeat the DSN
		}
		t.Cleanup(pool.Close)

		err = CheckNotSuperuser(pgscratch.Context(t), pool)
		var se *SuperuserError
		if !errors.As(err, &se) {
			t.Fatalf("CheckNotSuperuser on a role reaching superuser through a two-hop chain = %v, want *SuperuserError", err)
		}
	})
}
