package deployment

import (
	"context"
	"crypto/rand"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrDiscoverBusy: the runner already has a discover that has not ended.
	ErrDiscoverBusy = errors.New("deployment: a discover is already running on this runner")
	// ErrDiscoverRateLimited: the runner already had MaxDiscoversPerHour requests.
	ErrDiscoverRateLimited = errors.New("deployment: discover rate limit reached")
	// ErrDiscoverRejected: a report that cannot be applied, stored as a failed
	// discover: the runner broke the contract (a fingerprint under a key the
	// store never used), or the registry to compare with grew past
	// MaxDiscoverCarriers, or holds a carrier past the registration limits,
	// while the scan ran.
	ErrDiscoverRejected = errors.New("deployment: discover report rejected")
	// ErrDiscoverTooManyCarriers: the runner's host has more registered
	// carriers of the store than one discover may compare (MaxDiscoverCarriers).
	ErrDiscoverTooManyCarriers = errors.New("deployment: too many registered carriers for one discover")
)

// MaxDiscoverCarriers bounds the registered carriers one discover compares
// with: each one the scan does not see becomes an unknown_find line, so a
// report holds at most runnerproto.MaxDiscoverFindings findings plus this
// many unknown_find lines. A larger registry is refused at submit and, if it
// grew meanwhile, the report is rejected at apply: the answer stays bounded
// and is never cut short. An unknown_find line may carry a path and field as
// long as registration allows (maxKnownPath, maxKnownName), so this bound is
// lower than the runner's.
const MaxDiscoverCarriers = 1024

// maxKnownPath and maxKnownName are the registration limits of a carrier's
// target_path and target_field, in characters (internal/api, register). Any
// carrier registration accepted is compared; the check at apply only keeps
// the bound on the answer if a row ever bypassed registration.
const (
	maxKnownPath = 4096
	maxKnownName = 256
)

// DiscoverPageSize is the most lines one read of a report returns; the
// server sets it, a caller only says where the page starts. The largest page
// is the worst report the CLI already reads whole: MaxDiscoverFindings
// findings, of which at most MaxDiscoverCarriers are unknown_find lines.
const DiscoverPageSize = runnerproto.MaxDiscoverFindings

// MaxDiscoversPerHour bounds discover requests per runner, so a caller cannot
// keep a host reading files. The runner's own host policy caps it again.
const MaxDiscoversPerHour = 12

// DiscoverState is a discover request's state, a closed list.
type DiscoverState string

const (
	DiscoverPending   DiscoverState = "pending"
	DiscoverCompleted DiscoverState = "completed"
	DiscoverFailed    DiscoverState = "failed"
	DiscoverExpired   DiscoverState = "expired"
)

// DiscoverVerdict is the server's comparison of one finding with the carrier
// registry, a closed list.
type DiscoverVerdict string

const (
	// VerdictMatch: a registered carrier holds the current version.
	VerdictMatch DiscoverVerdict = "match"
	// VerdictStale: a registered carrier holds some other value.
	VerdictStale DiscoverVerdict = "stale"
	// VerdictSprawl: a permitted name in a place no carrier is registered for.
	VerdictSprawl DiscoverVerdict = "sprawl"
	// VerdictUnknownFind: a registered carrier of an active secret that the
	// complete scan did not find.
	VerdictUnknownFind DiscoverVerdict = "unknown_find"
)

// DiscoverRequest is authenticated metadata only: which runner scans, and for
// which store's fingerprint key. Paths and rules are never supplied: the
// runner's own host policy owns them.
type DiscoverRequest struct {
	OrgID     uuid.UUID
	RunnerID  uuid.UUID
	StoreID   uuid.UUID
	RequestID string
	Actor     audit.Actor
}

// DiscoverItem is one line of a report: path, variable name, keyed
// fingerprint, verdict. No value and no file content. Len is stored with the
// line but is not part of any answer (threat model 4.3.4.2).
type DiscoverItem struct {
	Verdict     DiscoverVerdict
	CarrierID   uuid.UUID // zero for a sprawl finding
	Path        string
	Name        string
	Fingerprint string
	Len         int
	// Incident is true while the line waits for a person.
	Incident bool
}

// DiscoverReport is the durable state of one discover request.
type DiscoverReport struct {
	RequestID  string
	RunnerID   uuid.UUID
	StoreID    uuid.UUID
	Host       string
	State      DiscoverState
	ErrorClass runnerproto.ErrorClass
	// Created is true only for the call that stored the request.
	Created bool
	// Offset is the line of the whole report Items starts at, Total the
	// lines of the whole report. Only a completed report has lines.
	Offset, Total int
	// AllMatch is true when the whole report, not only this page, is
	// completed and holds no line but a match.
	AllMatch bool
	Items    []DiscoverItem
}

// SubmitDiscover queues one discover job for a live enrolled runner of the
// organization and a builtin store of it. A second call with the same request
// id returns the first request; the same id for another runner or store is
// ErrConflict. A runner runs one discover at a time.
func (r *Repo) SubmitDiscover(ctx context.Context, in DiscoverRequest) (DiscoverReport, error) {
	if r == nil || r.pool == nil || r.journal == nil || r.trust == nil {
		return DiscoverReport{}, ErrUnavailable
	}
	if in.OrgID == uuid.Nil || in.RunnerID == uuid.Nil || in.StoreID == uuid.Nil || !reqid.Valid(in.RequestID) || in.Actor.ID == "" || !knownActor(in.Actor) {
		return DiscoverReport{}, ErrInvalidArgument
	}
	hash := bindHash("keep/discover/request/v1", in.OrgID.String(), in.RunnerID.String(), in.StoreID.String())
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var org uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, in.OrgID).Scan(&org); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DiscoverReport{}, ErrNotFound
		}
		return DiscoverReport{}, ErrUnavailable
	}
	var stored []byte
	err = tx.QueryRow(ctx, `SELECT request_hash FROM discovery_jobs WHERE org_id=$1 AND request_id=$2`, in.OrgID, in.RequestID).Scan(&stored)
	switch {
	case err == nil:
		if !equalHash(stored, hash[:]) {
			return DiscoverReport{}, ErrConflict
		}
		return readDiscover(ctx, tx, in.OrgID, in.RequestID, 0)
	case !errors.Is(err, pgx.ErrNoRows):
		return DiscoverReport{}, ErrUnavailable
	}
	var host string
	err = tx.QueryRow(ctx, `SELECT host FROM runners WHERE org_id=$1 AND id=$2 AND revoked_at IS NULL AND cert_not_after>clock_timestamp()`, in.OrgID, in.RunnerID).Scan(&host)
	if errors.Is(err, pgx.ErrNoRows) {
		return DiscoverReport{}, ErrNotFound
	}
	if err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	if _, err = r.trust(ctx, tx, in.OrgID, in.RunnerID); err != nil {
		return DiscoverReport{}, ErrNotFound
	}
	// The request is an organization-level act, so it may take the key of an
	// organization-owned store only: a workspace's, project's or user's store
	// key is not the caller's to hand to a host.
	var storeStatus, provider, ownerLevel string
	var ownerID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT status,provider,owner_scope_level,owner_scope_id FROM stores WHERE org_id=$1 AND id=$2`, in.OrgID, in.StoreID).Scan(&storeStatus, &provider, &ownerLevel, &ownerID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (storeStatus != "active" || provider != string(runnerproto.ProviderBuiltin) || ownerLevel != string(tenancy.LevelOrg) || ownerID != in.OrgID)) {
		return DiscoverReport{}, ErrNotFound
	}
	if err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	var registered int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM carriers c
	 JOIN secrets s ON s.org_id=c.org_id AND s.id=c.secret_id AND s.store_id=$2 AND s.status='active'
	 WHERE c.org_id=$1 AND c.host=$3 AND c.target_field<>'' AND c.target_kind IN (`+discoverableKinds+`)`, in.OrgID, in.StoreID, host).Scan(&registered); err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	if registered > MaxDiscoverCarriers {
		return DiscoverReport{}, ErrDiscoverTooManyCarriers
	}
	// A job whose runner never answered is over once its window has passed;
	// only the lifecycle column changes, which the frozen-row trigger allows.
	if _, err = tx.Exec(ctx, `UPDATE discovery_jobs SET status='expired' WHERE org_id=$1 AND runner_id=$2 AND status IN ('queued','issued') AND expires_at<=clock_timestamp()`, in.OrgID, in.RunnerID); err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	var busy bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_jobs WHERE org_id=$1 AND runner_id=$2 AND status IN ('queued','issued'))`, in.OrgID, in.RunnerID).Scan(&busy); err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	if busy {
		return DiscoverReport{}, ErrDiscoverBusy
	}
	var recent int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM discovery_jobs WHERE org_id=$1 AND runner_id=$2 AND created_at>clock_timestamp()-interval '1 hour'`, in.OrgID, in.RunnerID).Scan(&recent); err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	if recent >= MaxDiscoversPerHour {
		return DiscoverReport{}, ErrDiscoverRateLimited
	}
	jobID, err := uuid.NewV7()
	if err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	nonce := make([]byte, runnerproto.NonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	issued := time.Now().UTC().Truncate(time.Second)
	job := runnerproto.Job{JobID: jobID.String(), OrgID: in.OrgID.String(), RunnerID: in.RunnerID.String(),
		Secret: runnerproto.SecretRef{StoreID: in.StoreID.String(), Provider: runnerproto.ProviderBuiltin},
		Action: runnerproto.ActionDiscover, IssuedAt: issued, NotAfter: issued.Add(runnerproto.MaxJobTTL), Nonce: nonce}
	payload, err := runnerproto.EncodeJob(job)
	if err != nil {
		return DiscoverReport{}, ErrInvalidArgument
	}
	if _, err = tx.Exec(ctx, `INSERT INTO discovery_jobs(id,org_id,runner_id,request_id,request_hash,store_id,job_payload,nonce,expires_at,created_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp())`, jobID, in.OrgID, in.RunnerID, in.RequestID, hash[:], in.StoreID, payload, nonce, job.NotAfter); err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	record := audit.Record{OrgID: in.OrgID.String(), RequestID: in.RequestID, Scope: tenancy.Scope{Level: tenancy.LevelOrg, ID: in.OrgID}.String(), Actor: in.Actor, Action: audit.ActionCarrierDiscover,
		Target: audit.Target{RunnerID: in.RunnerID.String(), Host: host},
		Policy: audit.Policy{Decision: audit.DecisionAllow}, Result: audit.Result{Status: audit.StatusPending}}
	appended, err := r.journal.AppendTx(ctx, tx, record)
	if err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	rep, err := readDiscover(ctx, tx, in.OrgID, in.RequestID, 0)
	if err != nil {
		return DiscoverReport{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	r.journal.LogCommitted(ctx, appended)
	rep.Created = true
	return rep, nil
}

// DiscoverReport reads one page of a discover request of org: at most
// DiscoverPageSize lines from line offset of the whole report, in the order
// path, name, id. offset runs from 0 to the report's Total; past it is
// ErrInvalidArgument. A request id the organization never made is
// ErrNotFound, indistinguishable from another organization's.
func (r *Repo) DiscoverReport(ctx context.Context, org uuid.UUID, requestID string, offset int) (DiscoverReport, error) {
	if r == nil || r.pool == nil {
		return DiscoverReport{}, ErrUnavailable
	}
	if org == uuid.Nil || !reqid.Valid(requestID) {
		return DiscoverReport{}, ErrNotFound
	}
	return readDiscover(ctx, r.pool, org, requestID, offset)
}

// readDiscover derives an unanswered job past its deadline as expired, so a
// runner that never answered is visible without a sweeper. Lines are written
// only by the transaction that completes the job and never after it, so the
// order is fixed and an offset names the same line on every read; only a
// completed job has lines to page through.
func readDiscover(ctx context.Context, q querier, org uuid.UUID, requestID string, offset int) (DiscoverReport, error) {
	var rep DiscoverReport
	var id uuid.UUID
	var state, class string
	err := q.QueryRow(ctx, `SELECT j.id,j.runner_id,j.store_id,r.host,
	 CASE WHEN j.status IN ('queued','issued') THEN CASE WHEN j.expires_at<clock_timestamp() THEN 'expired' ELSE 'pending' END ELSE j.status END,
	 COALESCE(j.result->>'error_class','')
	 FROM discovery_jobs j JOIN runners r ON r.org_id=j.org_id AND r.id=j.runner_id
	 WHERE j.org_id=$1 AND j.request_id=$2`, org, requestID).Scan(&id, &rep.RunnerID, &rep.StoreID, &rep.Host, &state, &class)
	if errors.Is(err, pgx.ErrNoRows) {
		return DiscoverReport{}, ErrNotFound
	}
	if err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	rep.RequestID, rep.State, rep.ErrorClass = requestID, DiscoverState(state), runnerproto.ErrorClass(class)
	if rep.State != DiscoverCompleted {
		if offset != 0 {
			return DiscoverReport{}, ErrInvalidArgument
		}
		return rep, nil
	}
	// ok is a property of the whole report: one non-match line on the last
	// page makes the first page say so too.
	var nonMatch int
	if err = q.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE verdict<>'match')
	 FROM discovery_observations WHERE org_id=$1 AND job_id=$2`, org, id).Scan(&rep.Total, &nonMatch); err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	if offset < 0 || offset > rep.Total {
		return DiscoverReport{}, ErrInvalidArgument
	}
	rep.Offset, rep.AllMatch = offset, nonMatch == 0
	rows, err := q.Query(ctx, `SELECT verdict,carrier_id,path,name,fingerprint,length,incident_state IS NOT NULL
	 FROM discovery_observations WHERE org_id=$1 AND job_id=$2 ORDER BY path,name,id LIMIT $3 OFFSET $4`, org, id, DiscoverPageSize, offset)
	if err != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var it DiscoverItem
		var verdict string
		var carrier *uuid.UUID
		if rows.Scan(&verdict, &carrier, &it.Path, &it.Name, &it.Fingerprint, &it.Len, &it.Incident) != nil {
			return DiscoverReport{}, ErrUnavailable
		}
		it.Verdict = DiscoverVerdict(verdict)
		if carrier != nil {
			it.CarrierID = *carrier
		}
		rep.Items = append(rep.Items, it)
	}
	if rows.Err() != nil {
		return DiscoverReport{}, ErrUnavailable
	}
	return rep, nil
}

// DiscoverSummary counts a stored report, for the journal and the log.
type DiscoverSummary struct {
	Findings, Match, Stale, Sprawl, UnknownFind int
	// Incidents lists the lines that opened an incident.
	Incidents []DiscoverItem
}

// knownCarrier is a registered carrier a discover can be compared with.
type knownCarrier struct {
	id         uuid.UUID
	path, name string
	// scanName is name as a scan reports it (scanNameOf); name stays the
	// registered field and is what an unknown_find line shows.
	scanName    string
	fingerprint string
}

// compareDiscovery is the server's side of the discovery contract. Call it
// only with the findings of a scan the runner reported complete: a failed scan
// proves nothing about absence and never reaches it. Every fingerprint must
// carry a key id the store has used: the runner is told the key by the server,
// so any other id (also when the store has no versions at all) is a broken report, not a finding. versionFPs holds every
// fingerprint any version of the store's secrets ever had, so that an
// unregistered file holding a known value is told apart from an unrelated one.
func compareDiscovery(known []knownCarrier, findings []runnerproto.DiscoverFinding, keyIDs map[string]bool, versionFPs map[string]bool) ([]DiscoverItem, error) {
	// Two MCP servers in one file with the same variable are one scanned
	// name: the scan cannot tell them apart (it refuses the file when their
	// values differ), so one finding there accounts for both and the line
	// names one of them.
	byID := map[string]knownCarrier{}
	for _, k := range known {
		byID[k.path+"\x00"+k.scanName] = k
	}
	seen := map[string]bool{}
	var out []DiscoverItem
	for _, f := range findings {
		p, err := fingerprint.Parse(f.Fingerprint)
		if err != nil || !keyIDs[p.KeyID] {
			return nil, ErrDiscoverRejected
		}
		id := f.Path + "\x00" + f.Name
		if seen[id] {
			return nil, ErrDiscoverRejected
		}
		seen[id] = true
		it := DiscoverItem{Verdict: VerdictSprawl, Path: f.Path, Name: f.Name, Fingerprint: f.Fingerprint, Len: f.Len}
		if k, ok := byID[id]; ok {
			it.CarrierID = k.id
			it.Verdict = VerdictStale
			if equalString(k.fingerprint, f.Fingerprint) {
				it.Verdict = VerdictMatch
			}
		} else {
			it.Incident = versionFPs[f.Fingerprint]
		}
		out = append(out, it)
	}
	for _, k := range known {
		if !seen[k.path+"\x00"+k.scanName] {
			out = append(out, DiscoverItem{Verdict: VerdictUnknownFind, CarrierID: k.id, Path: k.path, Name: k.name, Incident: true})
		}
	}
	return out, nil
}

func equalString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := 0; i < len(a); i++ {
		x |= a[i] ^ b[i]
	}
	return x == 0
}

// discoverableKinds are the carrier kinds a scan can see and name: a variable
// in a file. A carrier without a field cannot be matched by name and is left
// out, so its absence is never reported.
const discoverableKinds = `'env-file','launchd-env','mcp-config','systemd-credential','yaml-scalar'`

// ApplyDiscoverResultTx stores a completed scan's comparison with the carrier
// registry in tx: one line per finding and one per registered carrier the scan
// did not find, an incident on the lines that need a person, and nothing else.
// It queues no rotation, deployment or verification: an unknown carrier never
// causes a reissue. A failed report stores nothing here. It is idempotent on
// (job, side, path, name): see observationKey.
func ApplyDiscoverResultTx(ctx context.Context, tx pgx.Tx, org uuid.UUID, job runnerproto.Job, res runnerproto.DiscoverResult) (DiscoverSummary, error) {
	if !res.OK {
		return DiscoverSummary{}, nil
	}
	jobID, err := uuid.Parse(job.JobID)
	if err != nil || job.Action != runnerproto.ActionDiscover || res.Validate() != nil {
		return DiscoverSummary{}, ErrDiscoverRejected
	}
	storeID, err := uuid.Parse(job.Secret.StoreID)
	if err != nil {
		return DiscoverSummary{}, ErrDiscoverRejected
	}
	runnerID, err := uuid.Parse(job.RunnerID)
	if err != nil {
		return DiscoverSummary{}, ErrDiscoverRejected
	}
	rows, err := tx.Query(ctx, `SELECT c.id,c.target_kind,c.target_path,c.target_field,v.fingerprint
	 FROM carriers c
	 JOIN runners r ON r.org_id=c.org_id AND r.id=$3 AND r.host=c.host
	 JOIN secrets s ON s.org_id=c.org_id AND s.id=c.secret_id AND s.store_id=$2 AND s.status='active'
	 JOIN LATERAL (SELECT fingerprint FROM secret_versions v WHERE v.org_id=s.org_id AND v.secret_id=s.id AND NOT v.disabled ORDER BY v.seal_seq DESC LIMIT 1) v ON true
	 WHERE c.org_id=$1 AND c.target_field<>'' AND c.target_kind IN (`+discoverableKinds+`)
	 ORDER BY c.id`, org, storeID, runnerID)
	if err != nil {
		return DiscoverSummary{}, ErrUnavailable
	}
	var known []knownCarrier
	for rows.Next() {
		var k knownCarrier
		var kind string
		if rows.Scan(&k.id, &kind, &k.path, &k.name, &k.fingerprint) != nil {
			rows.Close()
			return DiscoverSummary{}, ErrUnavailable
		}
		k.scanName = scanNameOf(kind, k.name)
		known = append(known, k)
	}
	rows.Close()
	if rows.Err() != nil {
		return DiscoverSummary{}, ErrUnavailable
	}
	if len(known) > MaxDiscoverCarriers {
		return DiscoverSummary{}, ErrDiscoverRejected
	}
	for _, k := range known {
		if utf8.RuneCountInString(k.path) > maxKnownPath || utf8.RuneCountInString(k.name) > maxKnownName {
			return DiscoverSummary{}, ErrDiscoverRejected
		}
	}
	keyIDs, versionFPs := map[string]bool{}, map[string]bool{}
	fpRows, err := tx.Query(ctx, `SELECT v.fingerprint FROM secret_versions v JOIN secrets s ON s.org_id=v.org_id AND s.id=v.secret_id
	 WHERE v.org_id=$1 AND s.store_id=$2`, org, storeID)
	if err != nil {
		return DiscoverSummary{}, ErrUnavailable
	}
	for fpRows.Next() {
		var fp string
		if fpRows.Scan(&fp) != nil {
			fpRows.Close()
			return DiscoverSummary{}, ErrUnavailable
		}
		if p, perr := fingerprint.Parse(fp); perr == nil {
			keyIDs[p.KeyID] = true
			versionFPs[fp] = true
		}
	}
	fpRows.Close()
	if fpRows.Err() != nil {
		return DiscoverSummary{}, ErrUnavailable
	}
	items, err := compareDiscovery(known, res.Findings, keyIDs, versionFPs)
	if err != nil {
		return DiscoverSummary{}, err
	}
	// One line per side, path and name: two registered carriers of different
	// secrets at one place are one unknown_find, and a retried report stores
	// nothing twice. The side (found by the scan or absent from it) is part
	// of the key so that a finding never swallows the unknown_find of a
	// carrier registered under the same name, nor the other way round.
	// Deduplicated here, not by a unique index, which a registration-length
	// path could overflow; the caller holds the job row FOR UPDATE, so one
	// job's applies never run side by side.
	seen := make(map[[3]string]bool, len(items))
	stored, err := tx.Query(ctx, `SELECT verdict,path,name FROM discovery_observations WHERE org_id=$1 AND job_id=$2`, org, jobID)
	if err != nil {
		return DiscoverSummary{}, ErrUnavailable
	}
	for stored.Next() {
		var verdict, path, name string
		if err := stored.Scan(&verdict, &path, &name); err != nil {
			stored.Close()
			return DiscoverSummary{}, ErrUnavailable
		}
		seen[observationKey(DiscoverVerdict(verdict), path, name)] = true
	}
	stored.Close()
	if stored.Err() != nil {
		return DiscoverSummary{}, ErrUnavailable
	}
	var sum DiscoverSummary
	for _, it := range items {
		key := observationKey(it.Verdict, it.Path, it.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		rowID, err := uuid.NewV7()
		if err != nil {
			return DiscoverSummary{}, ErrUnavailable
		}
		var carrier, incident any
		if it.CarrierID != uuid.Nil {
			carrier = it.CarrierID
		}
		if it.Incident {
			incident = "open"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_observations(id,org_id,job_id,runner_id,verdict,carrier_id,path,name,fingerprint,length,incident_state,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())`,
			rowID, org, jobID, runnerID, string(it.Verdict), carrier, it.Path, it.Name, it.Fingerprint, it.Len, incident); err != nil {
			return DiscoverSummary{}, ErrUnavailable
		}
		switch it.Verdict {
		case VerdictMatch:
			sum.Match++
		case VerdictStale:
			sum.Stale++
		case VerdictSprawl:
			sum.Sprawl++
		case VerdictUnknownFind:
			sum.UnknownFind++
		}
		if it.Verdict != VerdictUnknownFind {
			sum.Findings++
		}
		if it.Incident {
			sum.Incidents = append(sum.Incidents, it)
		}
	}
	return sum, nil
}

// observationKey is what one stored discovery line is unique by: an
// unknown_find line stands for a carrier the scan did not find, every other
// line for a finding, and the two never stand for one another.
func observationKey(v DiscoverVerdict, path, name string) [3]string {
	side := "found"
	if v == VerdictUnknownFind {
		side = "absent"
	}
	return [3]string{side, path, name}
}

// mcpEnvField is a registered mcp-config field, mcpServers.<server>.env.<VAR>
// (runnerproto's host policy rule); its last part is the name a scan reports.
var mcpEnvField = regexp.MustCompile(`^mcpServers\.[A-Za-z0-9_-]+\.env\.([A-Za-z_][A-Za-z0-9_]{0,127})$`)

// scanNameOf is the name a scan reports for a registered carrier's field. A
// scan reads an MCP file's env keys and names a variable by that key, while
// the registry keeps deploy's JSON path; every other kind's field already is
// the scanned name. A malformed MCP field has no scanned name: it maps to "",
// which no finding can carry (runnerproto refuses an empty name), so it
// matches nothing a scan reports and its absence stays an unknown_find.
// Keeping the field whole would not do: a bare "GATEWAY_TOKEN" or a dotted
// field is a valid finding name and would collide.
func scanNameOf(kind, field string) string {
	if kind == string(runnerproto.TargetMCPConfig) {
		if m := mcpEnvField.FindStringSubmatch(field); m != nil {
			return m[1]
		}
		return ""
	}
	return field
}
