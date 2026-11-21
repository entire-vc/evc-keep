package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/entire-vc/evc-keep/internal/reqid"
)

const (
	exitDiscoverFindings = 1
	exitDiscoverPending  = 4
)

// maxDiscoverResponseBytes bounds one read of a discovery report: one page,
// not the whole report (threat model 4.3.4.1). The server pages a report by
// at most deployment.DiscoverPageSize (runnerproto.MaxDiscoverFindings,
// 4096) lines; a page holds runner findings, each with a path of at most
// 1024 bytes and a name of at most 128 plain characters, and unknown_find
// lines, at most deployment.MaxDiscoverCarriers (1024) of them, each with a
// path and field as long as registration allows (4096 and 256 characters).
// The server's encoding/json may write any character as six bytes ('&' as
// \u0026): the worst valid page is under the 53 MB of a 4096-finding report
// plus 1024 such lines. Each page read gets 64 MiB; every other call stays
// at 1 MiB. A larger body fails closed with "too large", never truncates.
const maxDiscoverResponseBytes = 64 << 20

var discoverPollEvery = 2 * time.Second

// discoverResult mirrors one page of internal/api.CarrierDiscoverResult:
// findings carry where a name was seen, the name and a keyed fingerprint —
// never a value and never a length.
type discoverResult struct {
	OK         bool            `json:"ok"`
	RequestID  string          `json:"request_id"`
	RunnerID   string          `json:"runner_id"`
	StoreID    string          `json:"store_id"`
	Host       string          `json:"host"`
	State      string          `json:"state"`
	ErrorClass string          `json:"error_class,omitempty"`
	Offset     int             `json:"offset"`
	Total      int             `json:"total"`
	Findings   []discoverFound `json:"findings"`
}

type discoverFound struct {
	Verdict     string `json:"verdict"`
	CarrierID   string `json:"carrier_id,omitempty"`
	Path        string `json:"path"`
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Incident    bool   `json:"incident"`
}

// errDiscoverPages: the server's pages do not add up to one report. No page
// read after it is trusted and the run is never reported as clean.
var errDiscoverPages = errors.New("bad_response: discovery report pages do not add up")

// normalizeDiscover holds the server's closed strings to their closed sets, so
// a misbehaving server cannot push control sequences through the output.
func normalizeDiscover(r discoverResult) discoverResult {
	if !reqid.Valid(r.RequestID) {
		r.RequestID = "(unexpected value)"
	}
	switch r.State {
	case "pending", "completed", "failed", "expired":
	default:
		r.State = "(unexpected value)"
	}
	for i, f := range r.Findings {
		switch f.Verdict {
		case "match", "stale", "sprawl", "unknown_find":
		default:
			r.Findings[i].Verdict = "(unexpected value)"
		}
	}
	return r
}

// discoverWriter prints a report page by page, so a report of any length is
// never held whole: the head once, then each page's findings as they come.
// The JSON mode writes one document, the report's head with every page's
// findings in one array; its "offset" is dropped, "total" kept.
type discoverWriter struct {
	w      io.Writer
	asJSON bool
	rows   int
	// other counts printed lines that are not a match: a report that calls
	// itself ok with such a line does not add up.
	other int
}

func (d *discoverWriter) head(r discoverResult) error {
	if d.asJSON {
		h := r
		h.Findings = nil
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		if err := enc.Encode(struct {
			OK         bool   `json:"ok"`
			RequestID  string `json:"request_id"`
			RunnerID   string `json:"runner_id"`
			StoreID    string `json:"store_id"`
			Host       string `json:"host"`
			State      string `json:"state"`
			ErrorClass string `json:"error_class,omitempty"`
			Total      int    `json:"total"`
		}{h.OK, h.RequestID, h.RunnerID, h.StoreID, h.Host, h.State, h.ErrorClass, h.Total}); err != nil {
			return err
		}
		head := bytes.TrimSuffix(bytes.TrimSpace(buf.Bytes()), []byte("}"))
		_, err := d.w.Write(escapeJSONControls(append(head, []byte(`,"findings":[`)...)))
		return err
	}
	tw := newTabwriter(d.w)
	_, _ = fmt.Fprintf(tw, "request_id:\t%s\nhost:\t%s\nstate:\t%s\n", cell(r.RequestID), cell(r.Host), cell(r.State))
	if r.ErrorClass != "" {
		_, _ = fmt.Fprintf(tw, "error_class:\t%s\n", safeClass(r.ErrorClass))
	}
	if r.State == "completed" {
		_, _ = fmt.Fprintf(tw, "total:\t%s\n", strconv.Itoa(r.Total))
	}
	_, _ = fmt.Fprintln(tw, "VERDICT\tINCIDENT\tNAME\tPATH\tFINGERPRINT")
	return tw.Flush()
}

func (d *discoverWriter) page(fs []discoverFound) error {
	for _, f := range fs {
		if f.Verdict != "match" {
			d.other++
		}
	}
	if d.asJSON {
		var buf bytes.Buffer
		for _, f := range fs {
			if d.rows > 0 {
				buf.WriteByte(',')
			}
			b, err := json.Marshal(f)
			if err != nil {
				return err
			}
			buf.Write(b)
			d.rows++
		}
		_, err := d.w.Write(escapeJSONControls(buf.Bytes()))
		return err
	}
	tw := newTabwriter(d.w)
	for _, f := range fs {
		_, _ = fmt.Fprintf(tw, "%s\t%t\t%s\t%s\t%s\n", cell(f.Verdict), f.Incident, cell(f.Name), cell(f.Path), cell(f.Fingerprint))
		d.rows++
	}
	return tw.Flush()
}

func (d *discoverWriter) end() error {
	if !d.asJSON {
		return nil
	}
	_, err := io.WriteString(d.w, "]}\n")
	return err
}

// nextDiscoverPage holds a later page to the report its first page began:
// the same request, still completed, the same ok and total, starting exactly
// where it was asked, and at least one line and no more than are left.
// Anything else is errDiscoverPages.
func nextDiscoverPage(first, page discoverResult, offset int) error {
	if page.RequestID != first.RequestID || page.State != "completed" || page.OK != first.OK || page.Offset != offset || page.Total != first.Total ||
		len(page.Findings) == 0 || len(page.Findings) > first.Total-offset {
		return errDiscoverPages
	}
	return nil
}

// runCarriers dispatches "keep carriers <sub>"; only "discover" exists.
func runCarriers(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 || args[0] != "discover" {
		_, _ = fmt.Fprintln(stderr, `keep carriers: only "discover" is supported`)
		return 2
	}
	fs := flag.NewFlagSet("carriers discover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	runner := fs.String("runner", "", "runner id of the host to look at")
	store := fs.String("store", "", "id of the org-owned store whose fingerprint key the runner uses")
	requestID := fs.String("request-id", "", "idempotency key; repeat the same value to retry")
	wait := fs.Duration("wait", time.Minute, "how long to wait for the runner's report")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *runner == "" || *store == "" || *wait < 0 {
		_, _ = fmt.Fprintln(stderr, "keep carriers discover: --runner and --store are required; see keep --help")
		return 2
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	base := c.baseURL + "/orgs/" + url.PathEscape(c.org) + "/carriers/discover"
	status, raw, err := c.doEndpointMax("POST", base, map[string]any{"runner_id": *runner, "store_id": *store, "request_id": *requestID}, maxDiscoverResponseBytes)
	if err != nil {
		return reportErr(stderr, err)
	}
	var res discoverResult
	if err = decodeBody(raw, &res); err != nil {
		return reportErr(stderr, err)
	}
	res = normalizeDiscover(res)
	if status == 202 && reqid.Valid(res.RequestID) {
		_, _ = fmt.Fprintf(stderr, "keep carriers discover: waiting for request %s\n", res.RequestID)
	}
	deadline := time.Now().Add(*wait)
	for status == 202 && reqid.Valid(res.RequestID) && time.Now().Before(deadline) {
		time.Sleep(discoverPollEvery)
		if status, raw, err = c.doEndpointMax("GET", base+"/"+url.PathEscape(res.RequestID), nil, maxDiscoverResponseBytes); err != nil {
			return reportErr(stderr, err)
		}
		if err = decodeBody(raw, &res); err != nil {
			return reportErr(stderr, err)
		}
		res = normalizeDiscover(res)
	}
	// The first page fixes the report: 202 only while pending and 200 only
	// once it is not; it starts at line 0, holds no more lines than the
	// report, is not empty while the report has lines, and only a completed
	// report of a known request has lines or more pages.
	if (status == 202) != (res.State == "pending") || (status != 200 && status != 202) ||
		res.Offset != 0 || len(res.Findings) > res.Total || (len(res.Findings) == 0 && res.Total > 0) ||
		(res.State != "completed" && (res.Total != 0 || len(res.Findings) != 0)) ||
		(len(res.Findings) < res.Total && !reqid.Valid(res.RequestID)) {
		return reportErr(stderr, errDiscoverPages)
	}
	out := &discoverWriter{w: stdout, asJSON: g.jsonOut}
	if out.head(res) != nil || out.page(res.Findings) != nil {
		return reportErr(stderr, errors.New("cannot write discover result"))
	}
	first := res
	for offset := len(res.Findings); offset < first.Total; offset += len(res.Findings) {
		if status, raw, err = c.doEndpointMax("GET", base+"/"+url.PathEscape(first.RequestID)+"?offset="+strconv.Itoa(offset), nil, maxDiscoverResponseBytes); err != nil {
			return reportErr(stderr, err)
		}
		res = discoverResult{}
		if err = decodeBody(raw, &res); err != nil {
			return reportErr(stderr, err)
		}
		res = normalizeDiscover(res)
		if status != 200 || nextDiscoverPage(first, res, offset) != nil {
			return reportErr(stderr, errDiscoverPages)
		}
		if out.page(res.Findings) != nil {
			return reportErr(stderr, errors.New("cannot write discover result"))
		}
	}
	if out.end() != nil {
		return reportErr(stderr, errors.New("cannot write discover result"))
	}
	if first.OK && out.other > 0 {
		return reportErr(stderr, errDiscoverPages)
	}
	switch {
	case status == 202:
		return exitDiscoverPending
	case !first.OK:
		return exitDiscoverFindings
	}
	return 0
}
