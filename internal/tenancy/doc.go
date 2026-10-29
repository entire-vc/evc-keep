// Package tenancy is Keep's org → workspace → project → user hierarchy
// and the bottom-up name resolution algorithm defined in the tenancy
// model's §3.
//
// It never touches a secret's value: [Resolve] returns a [catalog.SecretRef]
// — metadata only — and this package holds no plaintext-zone import.
//
// It also never imports internal/identity: checking a found secret against
// the principal's rights (tenancy model §3 step 5) is deliberately left to
// internal/catalog.ResolveAuthorized, a layer that can depend on both this
// package and internal/identity without either of those two ever depending
// on each other — see that function's doc.
//
// Every repository function here takes org_id as an explicit parameter,
// taken by the caller from the authenticated identity, never from a
// request body or URL — the org_id filter is the primary tenant-isolation
// boundary (tenancy model §1, threat model §4).
package tenancy
