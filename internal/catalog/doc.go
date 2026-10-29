// Package catalog owns the store hierarchy a secret's reference is created
// into: Store, StoreBinding ("this scope's default store is this one"),
// OverrideLock ("below this level, this cannot be (re)defined / must live
// in one of these stores"), and the secrets/secret_versions metadata itself
// (tenancy model §1, §3).
//
// It never touches a secret's value: every type here is metadata (name,
// scope, class, a keyed fingerprint, a byte length) — see
// catalog_schema_test.go for the closed column list that keeps it that way,
// and CONTRIBUTING.md. It imports internal/tenancy for the shared Scope,
// Level and SecretRef vocabulary; internal/tenancy does not import this
// package back (Resolve has its own narrow, read-only queries — see
// tenancy/catalog_reads.go).
package catalog
