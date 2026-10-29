package mesh_test

// End-to-end rotation of a Mesh agent key: the real engine and adapters
// (internal/rotation), the real Mesh plugin over the in-process Mesh stub, a
// real PostgreSQL (KEEP_DATABASE_URL), and four carriers that are tmp files
// described by meshkey and read back by targets.VerifyCarrier. Only Mesh
// itself and the layout writer are stand-ins. The stub holds fake keys.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/entire-vc/evc-keep/internal/testutil/fdredirect"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/carriers/meshkey"
	"github.com/entire-vc/evc-keep/internal/rotation"
	kstore "github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/targets"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/provider/memory"
	prot "github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	e2ePath    = "builtin://mesh-e2e"
	e2eSubject = "Sage"
	fpBadValue = "kfp1:k1:zzzzzzzzzzzzzzzz"
	// carrier numbers, 1-based, in meshkey.For order
	cMCP, cMeshAgents, cFiddler, cEnv = 1, 2, 3, 4
)

// lockedBuf is the shared journal: the plugin's slog output and the incident
// records both land here, and the leak scan reads it.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// events is the ordered record of what Keep asked of Mesh and of the carriers.
type events struct {
	mu  sync.Mutex
	log []string
}

func (e *events) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.log = append(e.log, s)
}

func (e *events) all() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.log...)
}

func (e *events) count(prefix string) int {
	n := 0
	for _, s := range e.all() {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

// first and last return the index of the first/last event with the prefix, -1 if none.
func (e *events) first(prefix string) int {
	for i, s := range e.all() {
		if strings.HasPrefix(s, prefix) {
			return i
		}
	}
	return -1
}

func (e *events) last(prefix string) int {
	at := -1
	for i, s := range e.all() {
		if strings.HasPrefix(s, prefix) {
			at = i
		}
	}
	return at
}

// tracked wraps a provider so every call enters the event log.
type tracked struct {
	prot.RotationProvider
	ev *events
}

func (p *tracked) Issue(ctx context.Context, r prot.IssueRequest) (prot.Issued, error) {
	p.ev.add("issue")
	return p.RotationProvider.Issue(ctx, r)
}

func (p *tracked) Revoke(ctx context.Context, id string) error {
	p.ev.add("revoke " + id)
	return p.RotationProvider.Revoke(ctx, id)
}

// forwardOnly is a Mesh whose only way to a new key is regenerate-key: the new
// key ends every earlier one at once. The plugin itself never does this; the
// wrapper plays the part of the backend.
type forwardOnly struct {
	*mesh.Provider
	stub *stubMesh
}

func (forwardOnly) Capabilities() prot.Capabilities { return prot.Capabilities{DualKey: false} }

func (f forwardOnly) Issue(ctx context.Context, r prot.IssueRequest) (prot.Issued, error) {
	iss, err := f.Provider.Issue(ctx, r)
	if err != nil {
		return iss, err
	}
	f.stub.mu.Lock()
	defer f.stub.mu.Unlock()
	for id := range f.stub.keys {
		if id != iss.KeyID {
			f.stub.keys[id] = "revoked"
		}
	}
	return iss, nil
}

type incidentLog struct {
	mu       sync.Mutex
	recs     []rotation.IncidentRecord
	resolved []rotation.IncidentRecord
	out      *lockedBuf
}

// Resolve closes the Issue opened for the run; idempotent per run, and an
// Issue that was never opened cannot be resolved.
func (i *incidentLog) Resolve(_ context.Context, r rotation.IncidentRecord) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	opened := false
	for _, have := range i.recs {
		opened = opened || (have.RunID == r.RunID && have.Class == r.Class)
	}
	if !opened {
		return errors.New("resolve of an incident that was never opened")
	}
	for _, have := range i.resolved {
		if have.RunID == r.RunID && have.Class == r.Class {
			return nil
		}
	}
	i.resolved = append(i.resolved, r)
	_, _ = fmt.Fprintf(i.out, "incident resolved run=%s class=%s\n", r.RunID, r.Class)
	return nil
}

func (i *incidentLog) resolvedAll() []rotation.IncidentRecord {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]rotation.IncidentRecord(nil), i.resolved...)
}

func (i *incidentLog) Open(_ context.Context, r rotation.IncidentRecord) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, have := range i.recs { // idempotent per run
		if have.RunID == r.RunID && have.Class == r.Class {
			return nil
		}
	}
	i.recs = append(i.recs, r)
	_, _ = fmt.Fprintf(i.out, "incident run=%s class=%s carriers=%v forward_only=%t\n", r.RunID, r.Class, r.Carriers, r.ForwardOnly)
	return nil
}

func (i *incidentLog) all() []rotation.IncidentRecord {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]rotation.IncidentRecord(nil), i.recs...)
}

func (i *incidentLog) has(c rotation.Class) bool {
	for _, r := range i.all() {
		if r.Class == c {
			return true
		}
	}
	return false
}

func cid(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func carrierIndex(t *testing.T, c rotation.Carrier) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimLeft(c.ID[len(c.ID)-12:], "0"))
	if err != nil {
		t.Fatalf("carrier id %q", c.ID)
	}
	return n
}

type rig struct {
	t      *testing.T
	ctx    context.Context
	cancel context.CancelFunc
	pool   *pgxpool.Pool
	ref    rotation.Ref
	c      canary.Canary
	stub   *stubMesh
	prov   prot.RotationProvider
	ev     *events
	jr     *lockedBuf
	inc    *incidentLog
	mem    *memory.Provider
	files  []meshkey.Carrier
	roots  []string
	mkFPK  func() fingerprint.Key
	eng    *rotation.Engine
	std    func() string

	mu         sync.Mutex
	deployFail map[int]int  // carrier -> deploy calls that fail (-1: all)
	deployLie  map[int]bool // carrier -> Deploy reports success and writes nothing
	unhealthy  map[int]bool // carrier -> Verify reports a matching key but not healthy
	deployed   map[int]int  // carrier -> Deploy calls
	killAt     int          // when > 0 the Nth Deploy call cancels the run's context and dies
	killCalls  int
	killList   bool // the next List call cancels the run's context and dies
	lastFP     string

	oldKeyID, oldVal string
	neighbours       []string
}

func (r *rig) fpOf(v string) string {
	r.t.Helper()
	k := r.mkFPK()
	defer k.Wipe()
	fp, err := fingerprint.Compute(k, secret.New([]byte(v)))
	if err != nil {
		r.t.Fatal(err)
	}
	return fp
}

// seen is the leak detector: the canary in its encodings, with the base64
// shifts 1 and 2 (mod 3) checked here again on purpose.
func (r *rig) seen(s string) bool {
	vals := append([]string{r.c.Value(0), r.c.Value(1), r.c.Value(2)}, r.neighbours...)
	for _, v := range vals {
		if r.c.In(s) || strings.Contains(s, v) || strings.Contains(s, hex.EncodeToString([]byte(v))) {
			return true
		}
		for _, p := range []string{"", "x", "xx"} {
			enc := base64.StdEncoding.EncodeToString([]byte(p + v))
			if len(enc) > 8 && strings.Contains(s, enc[4:len(enc)-4]) {
				return true
			}
		}
	}
	return false
}

// captureStd redirects stdout and stderr to a pipe for the rest of the test.
func captureStd(t *testing.T) func() string {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	so, se := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = pw, pw
	// Code that writes to the descriptors directly (syscall.Write(2, ...),
	// a C library, println) never looks at the os variables: point fds 1 and 2
	// at the pipe too and restore them in finish.
	fd1, err1 := syscall.Dup(1)
	fd2, err2 := syscall.Dup(2)
	if err1 != nil || err2 != nil {
		t.Fatal("duplicate stdout/stderr descriptors")
	}
	if fdredirect.Dup2(int(pw.Fd()), 1) != nil || fdredirect.Dup2(int(pw.Fd()), 2) != nil {
		t.Fatal("redirect stdout/stderr descriptors")
	}
	// The standard logger and slog's default keep the *os.File they were
	// initialised with, so swapping the variables does not reach them.
	logOut, slogDef := log.Writer(), slog.Default()
	log.SetOutput(pw)
	slog.SetDefault(slog.New(slog.NewTextHandler(pw, nil)))
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&buf, pr); close(done) }()
	var once sync.Once
	var out string
	finish := func() string {
		once.Do(func() {
			_ = fdredirect.Dup2(fd1, 1)
			_ = fdredirect.Dup2(fd2, 2)
			_ = syscall.Close(fd1)
			_ = syscall.Close(fd2)
			os.Stdout, os.Stderr = so, se
			log.SetOutput(logOut)
			slog.SetDefault(slogDef)
			_ = pw.Close()
			<-done
			_ = pr.Close()
			out = buf.String()
		})
		return out
	}
	t.Cleanup(func() { finish() })
	return finish
}

func newRig(t *testing.T, dual bool) *rig {
	t.Helper()
	std := captureStd(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dsn := pgscratch.New(t, nil)
	mdb, err := kstore.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	mp, err := kstore.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err = mp.Up(ctx); err != nil {
		t.Fatal("migrate test database")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test pool")
	}
	t.Cleanup(pool.Close)
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES ($1,'e2e')`, org); err != nil {
		t.Fatal("insert organization")
	}

	c := canary.New()
	r := &rig{t: t, ctx: ctx, cancel: cancel, pool: pool, ref: rotation.Ref{OrgID: org, SecretID: uuid.New()}, c: c,
		ev: &events{}, jr: &lockedBuf{}, std: std, mem: memory.New(nil),
		deployFail: map[int]int{}, deployLie: map[int]bool{}, unhealthy: map[int]bool{}, deployed: map[int]int{},
		neighbours: []string{c.Value(8), c.Value(9)}, oldVal: c.Value(0)}
	r.inc = &incidentLog{out: r.jr}
	r.mkFPK = func() fingerprint.Key {
		k, err := fingerprint.NewKey("k1", []byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	agent := uuid.NewString()
	r.stub = newStub(t, agent, "")
	r.stub.values = []string{c.Value(0), c.Value(1), c.Value(2)}
	log := slog.New(slog.NewTextHandler(r.jr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mp2, err := mesh.New(mesh.Config{BaseURL: r.stub.srv.URL, AgentID: agent, Token: stubToken, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	var base prot.RotationProvider = mp2
	if !dual {
		base = forwardOnly{Provider: mp2, stub: r.stub}
	}
	r.prov = &tracked{RotationProvider: base, ev: r.ev}

	// Four carriers: each in its own directory, as tmp files.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := func(n string) string {
		d := filepath.Join(root, n)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		r.roots = append(r.roots, d)
		return d
	}
	r.files, err = meshkey.For(meshkey.Agent{Host: "e2e", Name: e2eSubject, LaneDir: dir("lane"), BinDir: dir("bin"),
		CfgDir: dir("cfg"), EnvDir: dir("env"), EnvFile: "sage.env"})
	if err != nil {
		t.Fatal(err)
	}

	// The key in use before the rotation: issued by Mesh, sealed as version 1,
	// laid out on all four carriers.
	iss, err := base.Issue(ctx, prot.IssueRequest{Subject: e2eSubject, RunID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	r.oldKeyID = iss.KeyID
	if _, err := r.mem.Write(ctx, provider.Ref{Path: e2ePath}, iss.Value); err != nil {
		t.Fatal(err)
	}
	for _, f := range r.files {
		r.layout(f, iss.Value)
	}

	pd := rotation.ProviderDeps{
		Provider: r.prov,
		Resolve: func(context.Context, rotation.Ref) (rotation.Target, error) {
			return rotation.Target{Store: r.mem, Ref: provider.Ref{Path: e2ePath}, Subject: e2eSubject}, nil
		},
		Ledger:         rotation.NewLedger(pool),
		Incident:       r.inc,
		FingerprintKey: func(context.Context) (fingerprint.Key, error) { return r.mkFPK(), nil },
	}
	r.eng = rotation.New(pool, rotation.Deps{
		Versions: &capVersions{ProviderVersions: rotation.NewProviderVersions(pd), r: r},
		Carriers: r, Deployer: r, Verifier: r,
		Revoker:  rotation.NewProviderRevoker(pd),
		Incident: r.inc,
	})
	r.ev.log = nil // the setup Issue is not part of any run
	return r
}

// capVersions remembers the fingerprint Prepare returned: it is what every
// carrier must report.
type capVersions struct {
	*rotation.ProviderVersions
	r *rig
}

func (c *capVersions) Prepare(ctx context.Context, ref rotation.Ref, id uuid.UUID) (rotation.Version, error) {
	v, err := c.ProviderVersions.Prepare(ctx, ref, id)
	if err == nil {
		c.r.mu.Lock()
		c.r.lastFP = v.Fingerprint
		c.r.mu.Unlock()
	}
	return v, err
}

func (r *rig) List(context.Context, rotation.Ref) ([]rotation.Carrier, error) {
	r.mu.Lock()
	kill := r.killList
	r.killList = false
	r.mu.Unlock()
	if kill {
		r.cancel()
		return nil, context.Canceled
	}
	out := make([]rotation.Carrier, len(r.files))
	for i := range r.files {
		out[i] = rotation.Carrier{ID: cid(i + 1)}
	}
	return out, nil
}

// layout writes v into the carrier's file field, leaving the neighbours alone.
// targets.Write cannot name an agents[name=...] member, so the fixture writes
// the files itself; reading back is the product's own VerifyCarrier.
func (r *rig) layout(f meshkey.Carrier, v secret.Value) {
	r.t.Helper()
	var val string
	secret.Expose(v, func(b []byte) { val = string(b) })
	var body []byte
	switch f.Kind {
	case meshkey.AgentEnv:
		body = []byte("OTHER=" + r.neighbours[0] + "\nMESH_AGENT_KEY=" + val + "\nLATER=" + r.neighbours[1] + "\n")
	case meshkey.MCPJSON:
		body, _ = json.Marshal(map[string]any{"mcpServers": map[string]any{"evc-mesh": map[string]any{
			"env": map[string]any{"MESH_AGENT_KEY": val, "OTHER": r.neighbours[0]}}}})
	default:
		member := "agent_key"
		if f.Kind == meshkey.FiddlerJSON {
			member = "mesh_agent_key"
		}
		body, _ = json.Marshal(map[string]any{"agents": []any{
			map[string]any{"name": "Other", member: r.neighbours[0]},
			map[string]any{"name": e2eSubject, member: val},
			map[string]any{"name": "Third", member: r.neighbours[1]},
		}})
	}
	tmp := f.Path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Rename(tmp, f.Path); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) Deploy(ctx context.Context, ref rotation.Ref, _ uuid.UUID, c rotation.Carrier, version string) error {
	n := carrierIndex(r.t, c)
	r.ev.add(fmt.Sprintf("deploy %d", n))
	r.mu.Lock()
	r.deployed[n]++
	r.killCalls++
	kill := r.killAt > 0 && r.killCalls == r.killAt
	fail := r.deployFail[n] != 0
	if r.deployFail[n] > 0 {
		r.deployFail[n]--
	}
	lie := r.deployLie[n]
	r.mu.Unlock()
	if kill {
		r.cancel()
		return context.Canceled
	}
	if fail {
		return errors.New("carrier refused")
	}
	if lie {
		return nil
	}
	v, _, err := r.mem.Resolve(ctx, provider.Ref{Path: e2ePath, Version: version})
	if err != nil {
		return err
	}
	defer v.Wipe()
	r.layout(r.files[n-1], v)
	return nil
}

func (r *rig) Verify(_ context.Context, _ rotation.Ref, c rotation.Carrier, _ string) (rotation.Report, error) {
	n := carrierIndex(r.t, c)
	r.mu.Lock()
	want := r.lastFP
	r.mu.Unlock()
	res, err := r.read(n, want)
	r.ev.add(fmt.Sprintf("verify %d %s", n, res))
	if err != nil {
		return rotation.Report{}, err
	}
	if res != targets.VerifyMatch {
		return rotation.Report{Fingerprint: fpBadValue, Healthy: true}, nil
	}
	r.mu.Lock()
	sick := r.unhealthy[n]
	r.mu.Unlock()
	return rotation.Report{Fingerprint: want, Healthy: !sick}, nil
}

// read asks the product's own verifier whether carrier n holds the key behind want.
func (r *rig) read(n int, want string) (targets.VerifyResult, error) {
	k := r.mkFPK()
	defer k.Wipe()
	return targets.VerifyCarrier(r.roots, n, r.files[n-1], want, k)
}

// holds: carrier n holds exactly the key with value v.
func (r *rig) holds(n int, v string) bool {
	res, err := r.read(n, r.fpOf(v))
	return err == nil && res == targets.VerifyMatch
}

func (r *rig) rotate(opts rotation.Options) (rotation.Result, error) {
	if opts.RetryDelay == 0 {
		opts.RetryDelay = time.Millisecond
	}
	if opts.Concurrency == 0 {
		opts.Concurrency = 1 // a fixed order of carriers
	}
	return r.eng.Rotate(r.ctx, r.ref, opts)
}

func (r *rig) keyActive(id string) bool {
	r.stub.mu.Lock()
	defer r.stub.mu.Unlock()
	return r.stub.keys[id] == "active"
}

func (r *rig) activeKeys() int {
	r.stub.mu.Lock()
	defer r.stub.mu.Unlock()
	n := 0
	for _, s := range r.stub.keys {
		if s == "active" {
			n++
		}
	}
	return n
}

// versionState reports whether a version of the secret still resolves, and to what.
func (r *rig) resolves(version string, want string) bool {
	v, _, err := r.mem.Resolve(r.ctx, provider.Ref{Path: e2ePath, Version: version})
	if err != nil {
		return false
	}
	defer v.Wipe()
	return v.Equal(secret.New([]byte(want)))
}

func (r *rig) disabled(version string) bool {
	_, _, err := r.mem.Resolve(r.ctx, provider.Ref{Path: e2ePath, Version: version})
	return errors.Is(err, provider.ErrDisabled)
}

// newKeyID is the one key in Mesh that is neither the old one nor revoked
// before the run: found by elimination from the stub's own list.
func (r *rig) newKeyID() string {
	r.stub.mu.Lock()
	defer r.stub.mu.Unlock()
	for id := range r.stub.keys {
		if id != r.oldKeyID {
			return id
		}
	}
	return ""
}

// noLeak is the surface scan: the journal (plugin log and incident lines), the
// run result and error texts, every database row of the rotation tables, and
// everything written to stdout and stderr while the test ran. The carrier
// files and the sealed store hold the key by design and are not scanned.
func (r *rig) noLeak(texts ...string) {
	r.t.Helper()
	surfaces := map[string]string{"journal": r.jr.String(), "events": strings.Join(r.ev.all(), "\n"),
		"texts": strings.Join(texts, "\n"), "stdout+stderr": r.std2()}
	var db strings.Builder
	trows, err := r.pool.Query(r.ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name LIKE 'rotation\_%' ORDER BY 1`)
	if err != nil {
		r.t.Fatal("list rotation tables")
	}
	var tables []string
	for trows.Next() {
		var n string
		if err := trows.Scan(&n); err != nil {
			r.t.Fatal(err)
		}
		tables = append(tables, n)
	}
	trows.Close()
	if len(tables) < 5 {
		r.t.Fatalf("scanning %d rotation tables, expected at least 5", len(tables))
	}
	for _, tbl := range tables {
		rows, err := r.pool.Query(r.ctx, "SELECT t::text FROM "+tbl+" t")
		if err != nil {
			r.t.Fatalf("dump %s", tbl)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				r.t.Fatal(err)
			}
			db.WriteString(s + "\n")
		}
		rows.Close()
	}
	surfaces["database"] = db.String()
	for _, rec := range append(r.inc.all(), r.inc.resolvedAll()...) {
		surfaces["incident"] += fmt.Sprintf("%+v\n", rec)
	}
	for name, s := range surfaces {
		if r.seen(s) {
			r.t.Errorf("a key value surfaced in %s", name)
		}
	}
	if db.Len() == 0 {
		r.t.Error("no database rows were scanned: the scan is blind")
	}
}

// std2 ends the capture and returns everything written to stdout/stderr and the
// default loggers since the rig was built: call noLeak once, at the end.
func (r *rig) std2() string { return r.std() }

// control: the detector must see the key where it really is, or "no leak" means nothing.
func (r *rig) positiveControl() {
	r.t.Helper()
	raw, err := os.ReadFile(r.files[cEnv-1].Path)
	if err != nil {
		r.t.Fatal(err)
	}
	if !r.seen(string(raw)) {
		r.t.Fatal("positive control: the leak detector does not see the key in a carrier file")
	}
}

func okRun(t *testing.T, res rotation.Result, err error) {
	t.Helper()
	if err != nil || res.State != rotation.StateDone {
		t.Fatalf("run: state=%s class=%s err=%t", res.State, res.Class, err != nil)
	}
}

// pendingRevoke: the new version is everywhere, the old one is not revoked yet.
func pendingRevoke(t *testing.T, res rotation.Result, err error) {
	t.Helper()
	if !errors.Is(err, rotation.ErrRevokePending) || errors.Is(err, rotation.ErrFailed) || res.State != rotation.StateRevokingOld || res.Class != rotation.ClassRevokeFailed {
		t.Fatalf("want a pending revoke, got state=%s class=%s err=%v", res.State, res.Class, err)
	}
}

func failedRun(t *testing.T, res rotation.Result, err error, class rotation.Class) {
	t.Helper()
	if !errors.Is(err, rotation.ErrFailed) || res.State != rotation.StateFailed || res.Class != class {
		t.Fatalf("want a failed run of class %s, got state=%s class=%s failed=%t", class, res.State, res.Class, errors.Is(err, rotation.ErrFailed))
	}
}

// (1) Variant A, every carrier takes the key: the new version is live, the old
// key is revoked only after every carrier was read back with the new fingerprint.
func TestE2EDualKeyAllCarriersOK(t *testing.T) {
	r := newRig(t, true)
	res, err := r.rotate(rotation.Options{})
	okRun(t, res, err)

	for i := 1; i <= 4; i++ {
		if !r.holds(i, r.c.Value(1)) {
			t.Errorf("carrier %d does not hold the new key", i)
		}
		if r.holds(i, r.oldVal) {
			t.Errorf("carrier %d still holds the old key", i)
		}
	}
	if r.keyActive(r.oldKeyID) || !r.keyActive(r.newKeyID()) || r.activeKeys() != 1 {
		t.Errorf("Mesh: old key active=%t, active keys=%d", r.keyActive(r.oldKeyID), r.activeKeys())
	}
	if !r.resolves("2", r.c.Value(1)) || !r.disabled("1") {
		t.Error("store: version 2 must hold the new key and version 1 must be disabled")
	}
	// Order: the revoke comes after the last verify, and every verify was a match.
	rv, lv := r.ev.first("revoke "), r.ev.last("verify ")
	if rv < 0 || lv < 0 || rv < lv {
		t.Errorf("revoke at %d, last verify at %d: the old key was revoked before confirmation\n%v", rv, lv, r.ev.all())
	}
	if r.ev.count("verify ") != 4 || r.ev.count("verify 1 match")+r.ev.count("verify 2 match")+r.ev.count("verify 3 match")+r.ev.count("verify 4 match") != 4 {
		t.Errorf("not every carrier was verified as a match: %v", r.ev.all())
	}
	if r.ev.count("issue") != 1 || r.ev.count("revoke ") != 1 || r.ev.first("issue") > r.ev.first("deploy ") {
		t.Errorf("issue/revoke counts or order: %v", r.ev.all())
	}
	if len(r.inc.all()) != 0 || len(r.inc.resolvedAll()) != 0 {
		t.Errorf("a clean run opened or resolved an incident: %+v", r.inc.all())
	}
	r.positiveControl()
	r.noLeak(fmt.Sprintf("%+v", res))
}

// (2) Variant A, one carrier fails: the version is not activated, the old key
// stays alive, the carrier is stale (still on the old key), an incident names it.
func TestE2EDualKeyBadCarrierDoesNotActivate(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig)
		class rotation.Class
		stale bool // the carrier is left on the old key
	}{
		{"layout refused", func(r *rig) { r.deployFail[cFiddler] = -1 }, rotation.ClassDeployFailed, true},
		{"layout reports ok, writes nothing", func(r *rig) { r.deployLie[cFiddler] = true }, rotation.ClassFingerprintMismatch, true},
		{"carrier holds the key but is not healthy", func(r *rig) { r.unhealthy[cFiddler] = true }, rotation.ClassUnhealthy, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, true)
			tc.setup(r)
			res, err := r.rotate(rotation.Options{})
			failedRun(t, res, err, tc.class)

			if !r.keyActive(r.oldKeyID) {
				t.Error("the old key was revoked although a carrier does not hold the new one")
			}
			if n := r.ev.count("revoke "); n != 0 {
				t.Errorf("Revoke was called %d times in a run with a bad carrier", n)
			}
			if r.disabled("1") || !r.resolves("1", r.oldVal) {
				t.Error("the old version was disabled: the new version was activated")
			}
			if tc.stale && (!r.holds(cFiddler, r.oldVal) || r.holds(cFiddler, r.c.Value(1))) {
				t.Error("the failed carrier must be stale: still on the old key")
			}
			if tc.class == rotation.ClassDeployFailed && r.deployed[cFiddler] != 1 {
				t.Errorf("a DualKey run retried the layout %d times: with a second valid key it gets one attempt", r.deployed[cFiddler])
			}
			var named bool
			for _, rec := range r.inc.all() {
				for _, id := range rec.Carriers {
					named = named || id == cid(cFiddler)
				}
			}
			if !named || !r.inc.has(tc.class) {
				t.Errorf("incident does not name the carrier and class: %+v", r.inc.all())
			}
			r.positiveControl()
			r.noLeak(fmt.Sprintf("%+v", res), err.Error())
		})
	}
}

// (3) Variant A, Revoke fails after every carrier verified: the new key is
// everywhere, the old one lives, the run says so in an incident.
func TestE2EDualKeyRevokeFailureOpensIncident(t *testing.T) {
	r := newRig(t, true)
	r.stub.mu.Lock()
	r.stub.delFail = 1 << 20 // Mesh refuses every DELETE
	r.stub.mu.Unlock()
	res, err := r.rotate(rotation.Options{})
	pendingRevoke(t, res, err)

	for i := 1; i <= 4; i++ {
		if !r.holds(i, r.c.Value(1)) {
			t.Errorf("carrier %d must already hold the new key", i)
		}
	}
	if !r.keyActive(r.oldKeyID) || r.disabled("1") {
		t.Error("old key or old version was ended although its revoke failed")
	}
	if !r.inc.has(rotation.ClassRevokeFailed) {
		t.Errorf("no 'old key alive' incident: %+v", r.inc.all())
	}
	if r.ev.last("verify ") > r.ev.first("revoke ") {
		t.Error("revoke was attempted before the last verification")
	}

	// Mesh still refuses: the same run id stays pending, no second incident.
	res1, err1 := r.rotate(rotation.Options{RunID: res.RunID})
	pendingRevoke(t, res1, err1)
	if n := len(r.inc.all()); n != 1 {
		t.Errorf("a repeated failure opened another incident (%d)", n)
	}

	// Mesh recovers; the same run id retries the revoke only and finishes.
	r.stub.mu.Lock()
	r.stub.delFail = 0
	r.stub.mu.Unlock()
	deploys := r.ev.count("deploy")
	res2, err2 := r.rotate(rotation.Options{RunID: res.RunID})
	okRun(t, res2, err2)
	if res2.RunID != res.RunID {
		t.Errorf("the retry ran under another run id")
	}
	if r.keyActive(r.oldKeyID) || !r.disabled("1") {
		t.Error("the old key or the old version is still alive after the retry")
	}
	if !r.keyActive(r.newKeyID()) {
		t.Error("the retry ended the new key")
	}
	if r.ev.count("issue") != 1 || r.ev.count("deploy") != deploys {
		t.Errorf("the retry issued a key (%d) or laid out again (%d->%d)", r.ev.count("issue"), deploys, r.ev.count("deploy"))
	}
	if n := len(r.inc.all()); n != 1 {
		t.Errorf("want exactly one incident across the failure and the retry, got %d", n)
	}
	// The retry closed the "old key alive" Issue: exactly one, and resolved.
	if rs := r.inc.resolvedAll(); len(rs) != 1 || rs[0].RunID != res.RunID || rs[0].Class != rotation.ClassRevokeFailed {
		t.Errorf("the incident was not resolved by the successful retry: %+v", rs)
	}
	r.positiveControl()
	r.noLeak(fmt.Sprintf("%+v %+v %+v", res, res1, res2), err.Error(), fmt.Sprint(err1))
}

// (3b) Mesh answers 204 to the DELETE but the key stays active: a revoke that is
// not confirmed by Check is a failure, not a success.
func TestE2EDualKeyRevokeNotConfirmed(t *testing.T) {
	r := newRig(t, true)
	r.stub.mu.Lock()
	r.stub.delNoop = true
	r.stub.mu.Unlock()
	res, err := r.rotate(rotation.Options{})
	pendingRevoke(t, res, err)
	if !r.keyActive(r.oldKeyID) || r.disabled("1") {
		t.Error("old key still active at Mesh, yet the old version was disabled")
	}
	if !r.inc.has(rotation.ClassRevokeFailed) {
		t.Errorf("no 'old key alive' incident: %+v", r.inc.all())
	}
	r.noLeak()
}

// (4) Variant B, forward-only: a layout failure after Issue leaves the key
// sealed in Keep, the layout is retried, nothing is rolled back, the incident
// says forward-only and names the carrier.
func TestE2EForwardOnlyFailureAfterIssue(t *testing.T) {
	r := newRig(t, false)
	r.deployFail[cEnv] = -1
	res, err := r.rotate(rotation.Options{DeployAttempts: 3})
	failedRun(t, res, err, rotation.ClassDeployFailed)

	if r.keyActive(r.oldKeyID) {
		t.Error("forward-only Mesh: the old key must be dead after Issue")
	}
	if !r.resolves("2", r.c.Value(1)) {
		t.Error("the new key is not sealed in Keep: it would be lost")
	}
	if r.disabled("2") || r.ev.count("revoke ") != 0 {
		t.Error("forward-only has no rollback: nothing may be revoked or disabled")
	}
	if !r.keyActive(r.newKeyID()) {
		t.Error("the new key must stay active in Mesh")
	}
	if r.deployed[cEnv] != 3 {
		t.Errorf("layout of the failing carrier was tried %d times, want 3", r.deployed[cEnv])
	}
	var fo bool
	for _, rec := range r.inc.all() {
		fo = fo || (rec.ForwardOnly && rec.Class == rotation.ClassDeployFailed)
	}
	if !fo {
		t.Errorf("no forward-only incident: %+v", r.inc.all())
	}
	// The carriers that took the key hold it; the failed one is on the dead key.
	if !r.holds(cMCP, r.c.Value(1)) || !r.holds(cEnv, r.oldVal) {
		t.Error("carrier states after the failed layout")
	}
	r.positiveControl()
	r.noLeak(fmt.Sprintf("%+v", res), err.Error())
}

// (5) The process dies: in the middle of the layout, and right after the key
// was issued and recorded. The run resumes by its id and asks Mesh for a key
// only once.
func TestE2EResumeAfterCrashDoesNotIssueAgain(t *testing.T) {
	for _, dual := range []bool{true, false} {
		for _, point := range []string{"mid-layout", "after-issue"} {
			t.Run(fmt.Sprintf("dual=%t/%s", dual, point), func(t *testing.T) {
				r := newRig(t, dual)
				if point == "mid-layout" {
					r.killAt = 3
				} else {
					r.killList = true
				}
				id := uuid.New()
				_, err := r.rotate(rotation.Options{RunID: id})
				if err == nil {
					t.Fatal("the killed run reported success")
				}
				if n := r.ev.count("issue"); n != 1 {
					t.Fatalf("issues before the crash: %d", n)
				}
				// A new process: fresh context, same database, same run id.
				r.ctx, r.cancel = context.WithCancel(context.Background())
				t.Cleanup(r.cancel)
				r.killAt = 0
				res, err := r.rotate(rotation.Options{RunID: id})
				okRun(t, res, err)
				if n := r.ev.count("issue"); n != 1 {
					t.Errorf("the resumed run asked Mesh for a key again (%d issues)", n)
				}
				for i := 1; i <= 4; i++ {
					if !r.holds(i, r.c.Value(1)) {
						t.Errorf("carrier %d does not hold the new key after the resume", i)
					}
				}
				if !dual && r.ev.count("revoke ") != 0 {
					t.Error("a forward-only run asked Mesh to revoke: the old key is already gone")
				}
				if r.activeKeys() != 1 || r.keyActive(r.oldKeyID) {
					t.Errorf("Mesh after resume: %d active keys, old active=%t", r.activeKeys(), r.keyActive(r.oldKeyID))
				}
				r.noLeak(fmt.Sprintf("%+v", res))
			})
		}
	}
}

// Forward-only, two clean rotations in a row: the second one has a recorded old
// key, and Keep still must not ask Mesh to revoke it (it ended at Issue).
func TestE2EForwardOnlyTwoRotations(t *testing.T) {
	r := newRig(t, false)
	res, err := r.rotate(rotation.Options{})
	okRun(t, res, err)
	res2, err := r.rotate(rotation.Options{})
	okRun(t, res2, err)
	if n := r.ev.count("revoke "); n != 0 {
		t.Errorf("a forward-only run asked Mesh to revoke %d times", n)
	}
	if r.ev.count("issue") != 2 || r.activeKeys() != 1 {
		t.Errorf("issues=%d active=%d", r.ev.count("issue"), r.activeKeys())
	}
	for i := 1; i <= 4; i++ {
		if !r.holds(i, r.c.Value(2)) {
			t.Errorf("carrier %d does not hold the second key", i)
		}
	}
	if !r.disabled("2") || !r.resolves("3", r.c.Value(2)) {
		t.Error("store: version 2 must be disabled and version 3 must hold the second key")
	}
	r.noLeak(fmt.Sprintf("state=%s %s", res.State, res2.State))
}

// The detector itself: a surface that does carry the key is reported. Without
// this the "no leak" checks above could pass on a broken detector.
func TestE2EDetectorSeesEveryEncoding(t *testing.T) {
	r := &rig{c: canary.New()}
	r.neighbours = nil
	for name, enc := range map[string]func(string) string{
		"raw":    func(s string) string { return "x " + s + " y" },
		"hex":    func(s string) string { return hex.EncodeToString([]byte(s)) },
		"b64":    func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
		"b64+1":  func(s string) string { return base64.StdEncoding.EncodeToString([]byte("x" + s)) },
		"b64+2":  func(s string) string { return base64.StdEncoding.EncodeToString([]byte("xx" + s)) },
		"b64url": func(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) },
	} {
		if !r.seen(enc(r.c.Value(0))) {
			t.Errorf("the detector is blind to %s", name)
		}
	}
	if r.seen("kfp1:k1:abcdefghijklmnop nothing here") {
		t.Error("the detector fires on a fingerprint")
	}
}

// The capture must catch what a stray print in product code would write: the
// stdout/stderr variables, the standard logger and slog's default.
func TestE2ECaptureSeesStrayOutput(t *testing.T) {
	get := captureStd(t)
	_, _ = fmt.Fprintln(os.Stdout, "marker-out")
	fmt.Fprintln(os.Stderr, "marker-err")
	log.Print("marker-log")
	slog.Info("marker-slog")
	_, _ = syscall.Write(2, []byte("marker-fd2\n"))
	_, _ = syscall.Write(1, []byte("marker-fd1\n"))
	println("marker-println")
	out := get()
	for _, m := range []string{"marker-out", "marker-err", "marker-log", "marker-slog", "marker-fd2", "marker-fd1", "marker-println"} {
		if !strings.Contains(out, m) {
			t.Errorf("the capture missed %s", m)
		}
	}
}
