package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

// deployResult mirrors internal/api.DeployResult field for field. It is
// decoded strictly: a server field outside this closed list is a broken
// server, and nothing from that response is printed.
type deployResult struct {
	OK          bool            `json:"ok"`
	RequestID   string          `json:"request_id"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Version     string          `json:"version,omitempty"`
	Healthcheck *deployHealth   `json:"healthcheck,omitempty"`
	ErrorClass  string          `json:"error_class,omitempty"`
	Approval    *deployApproval `json:"approval,omitempty"`
}

type deployHealth struct {
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checked_at"`
}

type deployApproval struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	URL    string `json:"url"`
}

const (
	exitDeployFailed   = 1
	exitDeployApproval = 3
	exitDeployPending  = 4
)

// deployPollEvery is how often the CLI asks the server for the runner's result.
var deployPollEvery = time.Second

func decodeDeployResult(raw []byte) (deployResult, error) {
	var r deployResult
	d := json.NewDecoder(io.LimitReader(bytes.NewReader(raw), 8192))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil || r.RequestID == "" {
		return deployResult{}, errors.New("invalid deploy response")
	}
	return r, nil
}

func runDeploy(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	name, rest, err := splitPositional(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "keep deploy: a secret name is required")
		return 2
	}
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	runner := fs.String("runner", "", "runner id")
	kind := fs.String("kind", "env-file", "target kind")
	target := fs.String("target", "", "target path on the runner host")
	field := fs.String("field", "", "variable or key inside the target")
	unit := fs.String("unit", "", "launchd label or systemd unit")
	consumer := fs.String("consumer", "", "service to restart: launchd:<label> or systemd:<unit>")
	mode := fs.String("mode", "0600", "file permission bits, octal")
	uid := fs.Int64("uid", -1, "owner uid of the written file")
	gid := fs.Int64("gid", -1, "owner gid of the written file")
	ws := fs.String("workspace", "", "workspace context")
	project := fs.String("project", "", "project context")
	requestID := fs.String("request-id", "", "idempotency key; repeat the same value to retry")
	wait := fs.Duration("wait", time.Minute, "how long to wait for the runner's result")
	if fs.Parse(rest) != nil || fs.NArg() != 0 || *runner == "" || *target == "" || *uid < 0 || *gid < 0 || *wait < 0 {
		_, _ = fmt.Fprintln(stderr, "keep deploy: --runner, --target, --uid and --gid are required; see keep --help")
		return 2
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	// An approval link and a request id are the only things the answer carries.
	body := map[string]any{"secret": name, "runner_id": *runner, "workspace_id": *ws, "project_id": *project,
		"request_id": *requestID, "target": map[string]any{"kind": *kind, "path": *target, "field": *field, "unit": *unit,
			"consumer": *consumer, "mode": *mode, "uid": *uid, "gid": *gid}}
	status, raw, err := c.doEndpoint("POST", c.baseURL+"/v1/deployments", body)
	if err != nil {
		return reportErr(stderr, err)
	}
	res, err := decodeDeployResult(raw)
	if err != nil {
		return reportErr(stderr, err)
	}
	if status == 202 && res.Approval == nil {
		// The id is the only handle for resuming a wait that ends early.
		_, _ = fmt.Fprintf(stderr, "keep deploy: waiting for request %s\n", res.RequestID)
	}
	deadline := time.Now().Add(*wait)
	for status == 202 && res.Approval == nil && time.Now().Before(deadline) {
		time.Sleep(deployPollEvery)
		status, raw, err = c.doEndpoint("GET", c.baseURL+"/v1/deployments/"+res.RequestID, nil)
		if err != nil {
			return reportErr(stderr, err)
		}
		if res, err = decodeDeployResult(raw); err != nil {
			return reportErr(stderr, err)
		}
	}
	if err := writeDeployResult(stdout, res, g.jsonOut); err != nil {
		return reportErr(stderr, errors.New("cannot write deploy result"))
	}
	switch {
	case res.Approval != nil:
		return exitDeployApproval
	case status == 202:
		return exitDeployPending
	case !res.OK:
		return exitDeployFailed
	}
	return 0
}

func writeDeployResult(w io.Writer, r deployResult, asJSON bool) error {
	if asJSON {
		return writeJSONValue(w, r)
	}
	tw := newTabwriter(w)
	_, _ = fmt.Fprintf(tw, "ok:\t%t\n", r.OK)
	_, _ = fmt.Fprintf(tw, "request_id:\t%s\n", cell(r.RequestID))
	if r.Fingerprint != "" {
		_, _ = fmt.Fprintf(tw, "fingerprint:\t%s\n", cell(r.Fingerprint))
	}
	if r.Version != "" {
		_, _ = fmt.Fprintf(tw, "version:\t%s\n", cell(r.Version))
	}
	if h := r.Healthcheck; h != nil {
		_, _ = fmt.Fprintf(tw, "healthcheck:\t%s\n", cell(h.Status))
	}
	if r.ErrorClass != "" {
		_, _ = fmt.Fprintf(tw, "error_class:\t%s\n", cell(r.ErrorClass))
	}
	if a := r.Approval; a != nil {
		_, _ = fmt.Fprintf(tw, "approval_required:\tid=%s status=%s url=%s\n", cell(a.ID), cell(a.Status), cell(a.URL))
	}
	return tw.Flush()
}
