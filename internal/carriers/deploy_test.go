package carriers

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
)

// deployFixture adds what a registration is checked against: an enrolled
// runner, the org's deployment policy and a completed deployment record.
type deployFixture struct {
	fixture
	svc    *Service
	runner uuid.UUID
	host   string
	md     Metadata
}

type runnerOpts struct {
	revoked, shared, legacy bool
	host                    string
	org                     uuid.UUID
}

func (f *deployFixture) addRunner(t *testing.T, o runnerOpts) uuid.UUID {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(t, err)
	id := uuid.New()
	var revoked any
	if o.revoked {
		revoked = time.Now().Add(-time.Minute)
	}
	if o.legacy {
		_, err = f.pool.Exec(ctx, `INSERT INTO runners(id,org_id,host,cert_serial,cert_not_after,revoked_at,hpke_public_key) VALUES($1,$2,$3,'01',now()+interval '1 day',$4,$5)`,
			id, o.org, o.host, revoked, key.PublicKey().Bytes())
	} else {
		_, err = f.pool.Exec(ctx, `INSERT INTO runners(id,org_id,host,cert_serial,cert_not_after,revoked_at,hpke_public_key,uid_shared,host_labels,attrs_source) VALUES($1,$2,$3,'01',now()+interval '1 day',$4,$5,$6,'{}','enroll_token')`,
			id, o.org, o.host, revoked, key.PublicKey().Bytes(), o.shared)
	}
	must(t, err)
	return id
}

func (f *deployFixture) setPolicy(t *testing.T, rules ...map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"rules": rules})
	must(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO deployment_policies(org_id,rules) VALUES($1,$2) ON CONFLICT (org_id) DO UPDATE SET rules=EXCLUDED.rules`, f.org, raw)
	must(t, err)
}

func (f *deployFixture) rule(runner uuid.UUID, kind, prefix string) map[string]any {
	return map[string]any{"secret_id": f.id.String(), "runner_id": runner.String(), "kind": kind, "path_prefix": prefix}
}

type jobOpts struct {
	runner   uuid.UUID
	org      uuid.UUID
	status   string
	version  string
	result   runnerproto.Result
	target   runnerproto.Target
	approved bool
	approval string // status of the approval when approved is set; default "approved"
	secret   uuid.UUID
}

func (f *deployFixture) addJob(t *testing.T, o jobOpts) {
	t.Helper()
	if o.org == uuid.Nil {
		o.org = f.org
	}
	if o.secret == uuid.Nil {
		o.secret = f.id
	}
	if o.approval == "" {
		o.approval = "approved"
	}
	if o.status == "" {
		o.status = "completed"
	}
	if o.version == "" {
		o.version = "v1"
	}
	target, err := json.Marshal(o.target)
	must(t, err)
	var versionID, storeID uuid.UUID
	must(t, f.pool.QueryRow(ctx, `SELECT v.id,s.store_id FROM secret_versions v JOIN secrets s ON s.org_id=v.org_id AND s.id=v.secret_id WHERE v.org_id=$1 AND v.secret_id=$2 AND v.provider_version='v1'`, f.org, o.secret).Scan(&versionID, &storeID))
	reqRow, jobID := uuid.New(), uuid.New()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	hash := bytes.Repeat([]byte{7}, 32)
	reqID := strings.ReplaceAll(reqRow.String(), "-", "")[:30]
	_, err = f.pool.Exec(ctx, `INSERT INTO deployment_requests(id,org_id,request_id,request_hash,target_key,secret_id,version_id,runner_id,secret_scope_level,secret_scope_id,target,decision)
	 VALUES($1,$2,$3,$4,$4,$5,$6,$7,'org',$2,$8,'queued')`, reqRow, f.org, reqID, hash, o.secret, versionID, o.runner, target)
	must(t, err)
	if o.approved {
		_, err = f.pool.Exec(ctx, `INSERT INTO approval_requests(id,org_id,deployment_request_id,binding_hash,target_key,requester_type,requester_id,requester_via,expires_at,status,decided_by,decided_at)
		 SELECT $1,$2,$3,$4,$4,'user',u.id,'api',now()+interval '1 day',$5::text,CASE WHEN $5::text='requested' THEN NULL ELSE u.id END,CASE WHEN $5::text='requested' THEN NULL ELSE now() END FROM (SELECT id FROM users WHERE org_id=$2 LIMIT 1) u`, uuid.New(), f.org, reqRow, hash, o.approval)
		must(t, err)
	}
	var result any
	if o.status == "completed" || o.status == "failed" {
		result, err = json.Marshal(o.result)
		must(t, err)
	}
	issued := any(nil)
	if o.status != "queued" && o.status != "expired" {
		issued = time.Now()
	}
	_, err = f.pool.Exec(ctx, `INSERT INTO deployment_jobs(id,org_id,runner_id,deployment_request_id,request_id,secret_id,version_id,secret_scope_level,secret_scope_id,store_id,store_owner_scope_level,store_owner_scope_id,provider,provider_ref,provider_version,catalog_name,catalog_class,job_payload,nonce,expires_at,created_at,status,issued_at,result)
	 VALUES($1,$2,$3,$4,$5,$6,$7,'org',$2,$8,'org',$2,'builtin','test/ref',$9,'TEST','test','\x00',$10,now()+interval '10 minutes',now(),$11,$12,$13)`,
		jobID, f.org, o.runner, reqRow, reqID, o.secret, versionID, storeID, o.version, nonce, o.status, issued, result)
	must(t, err)
}

func newDeployFixture(t *testing.T) *deployFixture {
	t.Helper()
	f := &deployFixture{fixture: setup(t), host: "runner-1.example.test"}
	_, err := f.pool.Exec(ctx, `INSERT INTO users(id,org_id,email) VALUES($1,$2,'approver@example.test')`, uuid.New(), f.org)
	must(t, err)
	f.runner = f.addRunner(t, runnerOpts{host: f.host, org: f.org})
	f.md = Metadata{Host: f.host, TargetKind: runnerproto.TargetEnvFile, TargetPath: "/srv/app/.env", TargetField: "DB_PASSWORD", Consumer: "systemd:app.service", HealthcheckRef: "app-health"}
	f.setPolicy(t, f.rule(f.runner, "env-file", "/srv/app"))
	f.svc = NewService(f.pool)
	return f
}

func (f *deployFixture) target() runnerproto.Target {
	return runnerproto.Target{Kind: f.md.TargetKind, Path: f.md.TargetPath, Field: f.md.TargetField, Consumer: f.md.Consumer, Mode: 0o600}
}

func (f *deployFixture) okJob(t *testing.T) {
	t.Helper()
	f.addJob(t, jobOpts{runner: f.runner, target: f.target(), result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
}

func TestServiceRegistersOnlyWhatWasDeployed(t *testing.T) {
	f := newDeployFixture(t)
	f.okJob(t)
	c, err := f.svc.Register(ctx, f.org, f.id, "v1", f.md)
	must(t, err)
	if c.LastFP != f.fp || c.State != Registered || c.Host != f.host || c.Version != "v1" || c.RunnerID != f.runner {
		t.Fatalf("carrier %+v", c)
	}
	rows, err := f.svc.List(ctx, f.org, f.id)
	must(t, err)
	if len(rows) != 1 || rows[0].ID != c.ID || rows[0].RunnerID != f.runner {
		t.Fatalf("list %+v", rows)
	}
	again, err := f.svc.Register(ctx, f.org, f.id, "v1", f.md)
	must(t, err)
	if again.ID != c.ID {
		t.Fatal("a retry must keep the carrier id")
	}
}

func TestServiceRefusesWithoutAConfirmedDeployment(t *testing.T) {
	for name, tc := range map[string]func(*testing.T, *deployFixture){
		"no job at all": func(*testing.T, *deployFixture) {},
		"job failed": func(t *testing.T, f *deployFixture) {
			f.addJob(t, jobOpts{runner: f.runner, target: f.target(), status: "failed", result: runnerproto.Result{ErrorClass: runnerproto.ErrClassPolicyDenied}})
		},
		"job still issued": func(t *testing.T, f *deployFixture) {
			f.addJob(t, jobOpts{runner: f.runner, target: f.target(), status: "issued"})
		},
		"result not ok": func(t *testing.T, f *deployFixture) {
			f.addJob(t, jobOpts{runner: f.runner, target: f.target(), result: runnerproto.Result{OK: false, Fingerprint: f.fp, Version: "v1"}})
		},
		"healthcheck failed": func(t *testing.T, f *deployFixture) {
			f.addJob(t, jobOpts{runner: f.runner, target: f.target(), result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1",
				Healthcheck: &runnerproto.Healthcheck{Status: runnerproto.HealthFailed, Kind: runnerproto.HealthKindUnitActive, CheckedAt: time.Now()}}})
		},
		"other version": func(t *testing.T, f *deployFixture) {
			f.addJob(t, jobOpts{runner: f.runner, target: f.target(), version: "v0", result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v0"}})
		},
		"job of another version reporting this one": func(t *testing.T, f *deployFixture) {
			f.addJob(t, jobOpts{runner: f.runner, target: f.target(), version: "v0", result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
		},
		"job of this version reporting another one": func(t *testing.T, f *deployFixture) {
			f.addJob(t, jobOpts{runner: f.runner, target: f.target(), version: "v1", result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v0"}})
		},
		"other field": func(t *testing.T, f *deployFixture) {
			tg := f.target()
			tg.Field = "OTHER_SLOT"
			f.addJob(t, jobOpts{runner: f.runner, target: tg, result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
		},
		"other path": func(t *testing.T, f *deployFixture) {
			tg := f.target()
			tg.Path = "/srv/app/other.env"
			f.addJob(t, jobOpts{runner: f.runner, target: tg, result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
		},
		"job of another host": func(t *testing.T, f *deployFixture) {
			other := f.addRunner(t, runnerOpts{host: "elsewhere.example.test", org: f.org})
			f.addJob(t, jobOpts{runner: other, target: f.target(), result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeployFixture(t)
			tc(t, f)
			if _, err := f.svc.Register(ctx, f.org, f.id, "v1", f.md); !errors.Is(err, ErrDeployment) {
				t.Fatalf("want ErrDeployment, got %v", err)
			}
			if rows, _ := f.svc.List(ctx, f.org, f.id); len(rows) != 0 {
				t.Fatal("a refused registration left a carrier")
			}
		})
	}
}

func TestServiceRefusesAnUnapprovedDestination(t *testing.T) {
	for name, tc := range map[string]func(*testing.T, *deployFixture, *Metadata){
		"host of no runner":   func(_ *testing.T, _ *deployFixture, md *Metadata) { md.Host = "nobody.example.test" },
		"path outside policy": func(_ *testing.T, _ *deployFixture, md *Metadata) { md.TargetPath = "/etc/other/.env" },
		"path prefix sibling": func(_ *testing.T, _ *deployFixture, md *Metadata) { md.TargetPath = "/srv/application/.env" },
		"kind outside policy": func(_ *testing.T, _ *deployFixture, md *Metadata) {
			md.TargetKind = runnerproto.TargetFile
			md.TargetField = ""
		},
		"no policy rules": func(t *testing.T, f *deployFixture, _ *Metadata) { f.setPolicy(t) },
		"rule of another secret": func(t *testing.T, f *deployFixture, _ *Metadata) {
			r := f.rule(f.runner, "env-file", "/srv/app")
			r["secret_id"] = uuid.NewString()
			f.setPolicy(t, r)
		},
		"revoked runner": func(t *testing.T, f *deployFixture, _ *Metadata) {
			_, err := f.pool.Exec(ctx, `UPDATE runners SET revoked_at=now() WHERE id=$1`, f.runner)
			must(t, err)
		},
		"runner of another org": func(t *testing.T, f *deployFixture, md *Metadata) {
			foreign := f.addRunner(t, runnerOpts{host: "foreign.example.test", org: f.other})
			f.setPolicy(t, f.rule(foreign, "env-file", "/srv/app"))
			md.Host = "foreign.example.test"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDeployFixture(t)
			f.okJob(t)
			md := f.md
			tc(t, f, &md)
			if ok, err := f.svc.ev.Approved(ctx, f.org, f.id, md); err != nil || ok {
				t.Fatalf("Approved = %v, %v", ok, err)
			}
		})
	}
	f := newDeployFixture(t)
	if ok, err := f.svc.ev.Approved(ctx, f.org, f.id, f.md); err != nil || !ok {
		t.Fatalf("positive control: Approved = %v, %v", ok, err)
	}
	if ok, _ := f.svc.ev.Approved(ctx, f.other, f.id, f.md); ok {
		t.Fatal("another organization's call was approved")
	}
}

func TestServiceProductionNeedsAnApprovedDeployment(t *testing.T) {
	f := newDeployFixture(t)
	_, err := f.pool.Exec(ctx, `UPDATE secrets SET class='prod' WHERE id=$1`, f.id)
	must(t, err)
	if ok, _ := f.svc.ev.Approved(ctx, f.org, f.id, f.md); ok {
		t.Fatal("a production destination was approved with no approved deployment")
	}
	f.addJob(t, jobOpts{runner: f.runner, target: f.target(), result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
	if ok, _ := f.svc.ev.Approved(ctx, f.org, f.id, f.md); ok {
		t.Fatal("a production destination was approved by a deployment nobody approved")
	}
	f.addJob(t, jobOpts{runner: f.runner, target: f.target(), approved: true, result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
	if ok, err := f.svc.ev.Approved(ctx, f.org, f.id, f.md); err != nil || !ok {
		t.Fatalf("approved production deployment: %v %v", ok, err)
	}
	_, err = f.pool.Exec(ctx, `UPDATE runners SET uid_shared=true WHERE id=$1`, f.runner)
	must(t, err)
	if ok, _ := f.svc.ev.Approved(ctx, f.org, f.id, f.md); ok {
		t.Fatal("a production destination on a shared-uid host was approved")
	}
}

// The healthcheck of a carrier is the kind the runner reported, never text
// from the caller.
func TestServiceTakesTheHealthcheckFromTheDeploymentRecord(t *testing.T) {
	f := newDeployFixture(t)
	c := canary.New()
	f.md.HealthcheckRef = c.Value(1)
	f.addJob(t, jobOpts{runner: f.runner, target: f.target(), result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1",
		Healthcheck: &runnerproto.Healthcheck{Status: runnerproto.HealthOK, Kind: runnerproto.HealthKindUnitActive, CheckedAt: time.Now()}}})
	got, err := f.svc.Register(ctx, f.org, f.id, "v1", f.md)
	must(t, err)
	rows, err := f.svc.List(ctx, f.org, f.id)
	must(t, err)
	if got.HealthcheckRef != "unit-active" || len(rows) != 1 || rows[0].HealthcheckRef != "unit-active" {
		t.Fatalf("healthcheck was not taken from the deployment record: %q / %+v", got.HealthcheckRef, rows)
	}
}

func TestServiceTakesTheFingerprintFromTheDeploymentRecord(t *testing.T) {
	f := newDeployFixture(t)
	other := fmt.Sprintf("kfp1:%s:aaaaaaaaaaaaaaaa", strings.Split(f.fp, ":")[1])
	f.addJob(t, jobOpts{runner: f.runner, target: f.target(), result: runnerproto.Result{OK: true, Fingerprint: other, Version: "v1"}})
	if _, err := f.svc.Register(ctx, f.org, f.id, "v1", f.md); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("a deployment that reports another fingerprint must be refused, got %v", err)
	}
}

func TestServiceNeverPutsHostOrPathInAnErrorOrALog(t *testing.T) {
	f := newDeployFixture(t)
	c := canary.New()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	slog.Info("capture control")
	md := f.md
	md.Host, md.TargetPath, md.TargetField, md.Consumer = c.Value(1)+".example.test", "/srv/"+c.Value(2), c.Value(3), "systemd:"+c.Value(4)
	_, e1 := f.svc.Register(ctx, f.org, f.id, "v1", md)
	_, e2 := f.svc.ev.Approved(ctx, f.org, f.id, md)
	_, e3 := f.svc.ev.Confirmed(ctx, f.org, f.id, "v1", md)
	for _, got := range []string{fmt.Sprint(e1), fmt.Sprintf("%+v %#v", e1, e1), fmt.Sprint(e2), fmt.Sprint(e3), logs.String()} {
		if c.In(got) {
			t.Fatalf("host or path leaked: %s", got)
		}
	}
	if !errors.Is(e1, ErrMetadata) || e2 != nil || !errors.Is(e3, ErrDeployment) || !strings.Contains(logs.String(), "capture control") {
		t.Fatalf("controls: %v %v %v", e1, e2, e3)
	}
}

func TestServiceRefusesAnUnapprovedHostBeforeLookingForADeployment(t *testing.T) {
	f := newDeployFixture(t)
	md := f.md
	md.Host = "nobody.example.test"
	if _, err := f.svc.Register(ctx, f.org, f.id, "v1", md); !errors.Is(err, ErrMetadata) {
		t.Fatalf("want ErrMetadata, got %v", err)
	}
	md = f.md
	md.TargetPath = "/etc/other/.env"
	f.addJob(t, jobOpts{runner: f.runner, target: runnerproto.Target{Kind: md.TargetKind, Path: md.TargetPath, Field: md.TargetField, Consumer: md.Consumer, Mode: 0o600},
		result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
	if _, err := f.svc.Register(ctx, f.org, f.id, "v1", md); !errors.Is(err, ErrMetadata) {
		t.Fatalf("a deployed but unapproved path must be ErrMetadata, got %v", err)
	}
}

// A destination whose deployment is older than a hundred newer deployments of
// the same secret to other destinations on the same host is still proven.
func TestServiceFindsTheDeploymentBehindManyNewerDeploymentsToOtherTargets(t *testing.T) {
	f := newDeployFixture(t)
	f.okJob(t)
	other := f.target()
	other.Path = "/srv/other/.env"
	for i := 0; i < maxJobsExamined+1; i++ {
		f.addJob(t, jobOpts{runner: f.runner, target: other, result: runnerproto.Result{OK: true, Fingerprint: f.fp, Version: "v1"}})
	}
	c, err := f.svc.Register(ctx, f.org, f.id, "v1", f.md)
	if err != nil {
		t.Fatalf("registration refused behind newer deployments to other targets: %v", err)
	}
	if c.State != Registered || c.Host != f.host {
		t.Fatalf("carrier %+v", c)
	}
}
