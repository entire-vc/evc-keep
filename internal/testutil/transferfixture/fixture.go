// Package transferfixture seeds one organization into every table the offline
// scoped transfer copies, with public test data only. Tests share it so each
// proves the same positive control.
package transferfixture

import (
	"context"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Seed writes at least one row into every copied table for org,
// with nullable columns both set and NULL, using only public test data.
func Seed(t testing.TB, ctx context.Context, db *pgxpool.Pool, org uuid.UUID, tag string) {
	t.Helper()
	id := func() uuid.UUID { return uuid.New() }
	ws, proj, store, secret := id(), id(), id(), id()
	u1, u2, agent, mws, mproj := id(), id(), id(), id(), id()
	o := org.String()
	stmts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (id, name, key_level) VALUES ($1, $2, 'workspace')`, []any{org, "org-" + tag}},
		{`INSERT INTO users (id, org_id, email, external_ref, status, removed_at) VALUES ($1,$2,$3,'ext-1','removed', now())`, []any{u1, org, "a-" + tag + "@example.test"}},
		{`INSERT INTO users (id, org_id, email) VALUES ($1,$2,$3)`, []any{u2, org, "b-" + tag + "@example.test"}},
		{`INSERT INTO agents (id, org_id, sponsor_user_id, name, external_ref) VALUES ($1,$2,$3,'agent-1','ext-a')`, []any{agent, org, u2}},
		{`INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1,$2,'org','svc-1')`, []any{id(), org}},
		{`INSERT INTO memberships (id, org_id, user_id, scope, role) VALUES ($1,$2,$3,'org','admin')`, []any{id(), org, u2}},
		{`INSERT INTO agent_grants (id, org_id, agent_id, permission) VALUES ($1,$2,$3,'rotate')`, []any{id(), org, agent}},
		{`INSERT INTO workspaces (id, org_id, name, external_ref) VALUES ($1,$2,'ws-1','ext-w')`, []any{ws, org}},
		{`INSERT INTO projects (id, org_id, workspace_id, name) VALUES ($1,$2,$3,'proj-1')`, []any{proj, org, ws}},
		{`INSERT INTO stores (id, org_id, provider, name, owner_scope_level, owner_scope_id) VALUES ($1,$2,'builtin','store-1','org',$2)`, []any{store, org}},
		{`INSERT INTO store_bindings (id, org_id, scope_level, scope_id, store_id) VALUES ($1,$2,'org',$2,$3)`, []any{id(), org, store}},
		{`INSERT INTO override_locks (id, org_id, scope_level, scope_id, selector_class, mode, allowed_store_ids) VALUES ($1,$2,'org',$2,'prod','store',ARRAY[$3::uuid])`, []any{id(), org, store}},
		{`INSERT INTO secrets (id, org_id, scope_level, scope_id, name, class, type, store_id, provider_ref, description, deployed_version) VALUES ($1,$2,'org',$2,'secret-1','prod','api_key',$3,'ref-1','desc','v1')`, []any{secret, org, store}},
		{`INSERT INTO secret_versions (id, org_id, secret_id, provider_version, fingerprint, length) VALUES ($1,$2,$3,'v1','kfp1:k1:abcdefghijklmnop',12)`, []any{id(), org, secret}},
		{`INSERT INTO keep_org_key_level (org_id, level, updated_by) VALUES ($1,'workspace','admin')`, []any{o}},
		{`INSERT INTO keep_kek (id, org_id, domain_key, domain_org, root_key_id, wrapped, state) VALUES ($1,$2,'user',$2,'root-1','\x0102','active')`, []any{"kek-" + tag, o}},
		{`INSERT INTO keep_kek (id, org_id, domain_key, domain_org, root_key_id, wrapped, state) VALUES ($1,$2,'pki',$2,'root-1','\x0102','active')`, []any{"kek-ca-" + tag, o}},
		{`INSERT INTO keep_kek (id, org_id, domain_key, domain_org, root_key_id, wrapped, state) VALUES ($1,$2,'pki',$2,'root-1','\x0102','retired')`, []any{"kek-sign-" + tag, o}},
		{`INSERT INTO keep_envelope (store_org, secret_id, name, version, kek_id, wrapped_dek, ciphertext, status) VALUES ($1,$2,'secret-1',1,$3,'\x0304','\x0506','active')`, []any{o, secret.String(), "kek-" + tag}},
		{`INSERT INTO keep_envelope (store_org, secret_id, name, version, ciphertext, status) VALUES ($1,$2,'secret-1',2,'\x07','erased')`, []any{o, secret.String()}},
		{`INSERT INTO org_ca (org_id, ca_cert_der, ca_kek_id, ca_wrapped_dek, ca_ciphertext, sign_key_id, sign_pub_key, sign_kek_id, sign_wrapped_dek, sign_ciphertext) VALUES ($1,'\x01',$2,'\x02','\x03','sign-1',decode(repeat('ab',32),'hex'),$3,'\x04','\x05')`, []any{org, "kek-ca-" + tag, "kek-sign-" + tag}},
		{`INSERT INTO mesh_installations (workspace_id, org_id, mesh_url, installed_by, token_signed_at, mode) VALUES ($1,$2,'https://mesh.example.test',$3,42,'store')`, []any{mws, org, u2}},
		{`INSERT INTO mesh_events (workspace_id, event_id, event_type) VALUES ($1,'ev-1','project.created')`, []any{mws}},
		{`INSERT INTO mesh_members (workspace_id, user_id, role, status, state_at) VALUES ($1,$2,'admin','active', now())`, []any{mws, u2}},
		{`INSERT INTO mesh_projects (workspace_id, project_id, slug, name, status, state_at, orphaned_at) VALUES ($1,$2,'p','P','orphaned', now(), now())`, []any{mws, mproj}},
		{`INSERT INTO mesh_agents (workspace_id, agent_id, slug, sponsor_user_id, status, state_at) VALUES ($1,$2,'a',$3,'active', now())`, []any{mws, agent, u2}},
		{`INSERT INTO mesh_agent_keys (workspace_id, agent_id, key_id, label, status, state_at) VALUES ($1,$2,'key-1','l','active', now())`, []any{mws, agent}},
		{`INSERT INTO mesh_sync_state (workspace_id, cursor, dirty_seq, synced_seq, last_sync_at, last_result, orphaned_count) VALUES ($1,'c',3,2, now(),'ok',1)`, []any{mws}},
		{`INSERT INTO mesh_secret_nonces (workspace_id, nonce) VALUES ($1,'abcdefghijklmnop')`, []any{mws}},
		{`INSERT INTO mesh_user_links (workspace_id, mesh_user_id, org_id, user_id) VALUES ($1,$2,$3,$4)`, []any{mws, id(), org, u2}},
		{`INSERT INTO mesh_rotator_bindings (workspace_id, org_id, bound_by) VALUES ($1,$2,$3)`, []any{mws, org, u2}},
	}
	for i, s := range stmts {
		if _, err := db.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed statement %d: %v", i, err)
		}
	}
	_ = proj
	// The audit chain is written by the real journal so its hashes verify.
	j := audit.NewJournal(db)
	for _, action := range []audit.Action{audit.ActionSecretCreateRef, audit.ActionSecretDisable} {
		if _, err := j.Append(ctx, audit.Record{
			OrgID: o, RequestID: "req-1", Scope: "org:" + o,
			Actor:  audit.Actor{Type: audit.ActorUser, ID: "u", Via: audit.ViaAPI},
			Action: action, Result: audit.Result{Status: audit.StatusOK},
		}); err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}
}

// DropTenancyWorkspaces turns a seeded organization into a native Mesh
// store-mode one: Mesh's own installation creates no tenancy workspace and no
// project, so the fixture's are removed and nothing else is touched. It edits
// only the synthetic test source.
func DropTenancyWorkspaces(t testing.TB, ctx context.Context, db *pgxpool.Pool, org uuid.UUID) {
	t.Helper()
	for _, q := range []string{
		`DELETE FROM projects WHERE org_id = $1`,
		`DELETE FROM workspaces WHERE org_id = $1`,
	} {
		if _, err := db.Exec(ctx, q, org); err != nil {
			t.Fatalf("drop tenancy workspaces: %v", err)
		}
	}
}
