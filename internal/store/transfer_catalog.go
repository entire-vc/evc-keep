package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// catalogQueries read the live catalog of the current schema, one ordered
// text line per object. Together they cover what a transfer must not find
// changed: columns (type, nullability, default, identity, generated),
// constraints, indexes, triggers (with their enabled state), functions,
// sequences (definition and owner) and row-level security. They read
// definitions only, never table rows, and exclude the goose bookkeeping table.
var catalogQueries = []struct{ kind, sql string }{
	// Every relation of the schema by kind (tables, partitioned tables, views,
	// materialized views, foreign tables, sequences, indexes, composite types),
	// so an object the other queries do not describe still changes the digest.
	// Partition keys and view bodies are part of the definition.
	{"relation", `SELECT c.relname || ' kind=' || c.relkind::text || ' persistence=' || c.relpersistence::text ||
			' partition=' || c.relispartition || ' partkey=' ||
			CASE WHEN c.relkind = 'p' THEN pg_get_partkeydef(c.oid) ELSE '' END || ' body=' ||
			CASE WHEN c.relkind IN ('v', 'm') THEN pg_get_viewdef(c.oid) ELSE '' END
		FROM pg_class c
		WHERE c.relnamespace = current_schema()::regnamespace AND c.relname <> 'goose_db_version'
		ORDER BY c.relname`},
	// Enums, domains and ranges of the schema; the implicit row types of
	// tables are the relations above.
	{"type", `SELECT t.typname || ' type=' || t.typtype::text || ' labels=' ||
			coalesce((SELECT string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid = t.oid), '') ||
			' base=' || coalesce(format_type(t.typbasetype, t.typtypmod), '')
		FROM pg_type t
		WHERE t.typnamespace = current_schema()::regnamespace AND t.typtype IN ('e', 'd', 'r', 'm')
		ORDER BY t.typname`},
	{"column", `SELECT c.relname || '.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) ||
			' notnull=' || a.attnotnull || ' default=' || coalesce(pg_get_expr(d.adbin, d.adrelid), '') ||
			' identity=' || a.attidentity::text || ' generated=' || a.attgenerated::text
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r', 'p')
		  AND c.relname <> 'goose_db_version' AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY c.relname, a.attname`},
	{"constraint", `SELECT c.relname || '.' || k.conname || ' ' || pg_get_constraintdef(k.oid)
		FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
		WHERE c.relnamespace = current_schema()::regnamespace AND c.relname <> 'goose_db_version'
		ORDER BY c.relname, k.conname`},
	{"index", `SELECT indexdef FROM pg_indexes
		WHERE schemaname = current_schema() AND tablename <> 'goose_db_version' ORDER BY indexname`},
	{"trigger", `SELECT c.relname || '.' || t.tgname || ' enabled=' || t.tgenabled::text || ' ' || pg_get_triggerdef(t.oid)
		FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		WHERE c.relnamespace = current_schema()::regnamespace AND NOT t.tgisinternal
		  AND c.relname <> 'goose_db_version' ORDER BY c.relname, t.tgname`},
	// Every routine kind: functions, procedures, window functions and
	// aggregates (pg_get_functiondef refuses aggregates, so they are named).
	{"function", `SELECT p.prokind::text || ' ' || CASE WHEN p.prokind = 'a'
			THEN p.oid::regprocedure::text || ' ' || p.prosrc ELSE pg_get_functiondef(p.oid) END
		FROM pg_proc p
		WHERE p.pronamespace = current_schema()::regnamespace
		ORDER BY p.proname, p.oid::regprocedure::text`},
	// Sequence definitions and which column owns each: pg_sequences carries
	// everything but the current value (a row-derived counter, not schema).
	{"sequence", `SELECT q.sequencename || ' ' || q.data_type::text || ' start=' || q.start_value ||
			' min=' || q.min_value || ' max=' || q.max_value || ' inc=' || q.increment_by ||
			' cycle=' || q.cycle || ' cache=' || q.cache_size || ' owned_by=' ||
			coalesce(t.relname || '.' || a.attname, '')
		FROM pg_sequences q
		JOIN pg_class s ON s.relname = q.sequencename AND s.relnamespace = current_schema()::regnamespace
		LEFT JOIN pg_depend d ON d.classid = 'pg_class'::regclass AND d.objid = s.oid
			AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')
		LEFT JOIN pg_class t ON t.oid = d.refobjid
		LEFT JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
		WHERE q.schemaname = current_schema() ORDER BY q.sequencename`},
	{"rls", `SELECT c.relname || ' rls=' || c.relrowsecurity || ' force=' || c.relforcerowsecurity
		FROM pg_class c
		WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r', 'p')
		  AND c.relname <> 'goose_db_version' ORDER BY c.relname`},
	{"policy", `SELECT tablename || '.' || policyname || ' ' || cmd || ' ' || permissive || ' ' ||
			coalesce(qual, '') || ' | ' || coalesce(with_check, '')
		FROM pg_policies WHERE schemaname = current_schema() ORDER BY tablename, policyname`},
}

// LiveCatalogID returns the digest of the live schema catalog read inside tx.
// A transfer runs only when it equals scopedtransfer.CatalogID on both the
// source and the target: matching goose versions and embedded migration text
// do not prove the database itself was not altered by hand. The digest is
// public schema metadata, never a value fingerprint.
func LiveCatalogID(ctx context.Context, tx pgx.Tx) (string, error) {
	h := sha256.New()
	_, _ = h.Write([]byte("keep-scoped-transfer-catalog-v1\x00"))
	put := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(s))
	}
	for _, q := range catalogQueries {
		lines, err := queryStrings(ctx, tx, q.sql)
		if err != nil {
			return "", ErrTransferInventory
		}
		put(q.kind)
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(lines)))
		_, _ = h.Write(n[:])
		for _, l := range lines {
			put(l)
		}
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
