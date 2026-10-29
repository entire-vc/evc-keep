package loop

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/runner"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// Transport is the runner's three calls to the server (the contract's
// routes). Errors carry a status class at most, never a response body.
type Transport interface {
	// NextJob returns the next signed job, or nil, nil after the long poll
	// found none.
	NextJob(ctx context.Context) (*runnerproto.SignedJob, error)
	// FetchValue asks once for the job's value and fingerprint-key envelopes.
	FetchValue(ctx context.Context, jobID string) (runnerproto.ValueEnvelope, error)
	// SendResult reports the closed Result. ErrRefused means the server will
	// never accept it.
	SendResult(ctx context.Context, jobID string, r runnerproto.Result) error
}

// ErrRefused is the server's job-level refusal (404): retrying cannot help.
var ErrRefused = errors.New("loop: server refused the request")

// ErrTransport is any other failure: network, certificate, server error.
// ErrOutbox means the runner could not record a job's outcome on disk. The
// loop stops rather than run jobs it cannot report.
var ErrOutbox = errors.New("loop: outbox unusable")

// ErrTransport marks a network or server failure.
var ErrTransport = errors.New("loop: server unavailable")

const (
	pollTimeout    = 40 * time.Second // the server holds a poll for 25 s
	requestTimeout = 30 * time.Second
	maxJobBody     = 1 << 20
	maxEnvBody     = 2 << 20 // a 1 MiB value, sealed and base64-encoded, plus the key envelope
)

// HTTPTransport speaks to Keep Server's runner listener over mTLS.
type HTTPTransport struct {
	base   string
	client *http.Client
}

// NewHTTPTransport builds the mTLS client from the enrolled credential.
// server must be an https URL. serverCA, if non-nil, is the only CA trusted
// for the listener's certificate.
func NewHTTPTransport(server string, cred runner.Credential, serverCA *x509.CertPool) (*HTTPTransport, error) {
	if !strings.HasPrefix(server, "https://") {
		return nil, errors.New("loop: server must be an https URL")
	}
	cert := tls.Certificate{Certificate: [][]byte{cred.CertDER}, PrivateKey: cred.Key}
	return &HTTPTransport{
		base: strings.TrimRight(server, "/"),
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: serverCA,
			}},
			// A redirect must not carry the client certificate or a job id elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (t *HTTPTransport) do(ctx context.Context, timeout time.Duration, method, path string, body []byte) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.base+path, rd)
	if err != nil {
		cancel()
		return nil, nil, ErrTransport
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := t.client.Do(req) //nolint:gosec // G704: the server URL is the operator's own -server flag
	if err != nil {
		cancel()
		return nil, nil, ErrTransport // the transport error text can name the URL
	}
	return resp, cancel, nil
}

func statusErr(code int) error {
	if code == http.StatusNotFound {
		return ErrRefused
	}
	return fmt.Errorf("%w: status %d", ErrTransport, code)
}

func decodeClosed(r io.Reader, limit int64, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(b)) > limit {
		return ErrTransport
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrTransport
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrTransport
	}
	return nil
}

// NextJob implements Transport.
func (t *HTTPTransport) NextJob(ctx context.Context) (*runnerproto.SignedJob, error) {
	resp, cancel, err := t.do(ctx, pollTimeout, http.MethodGet, "/runners/jobs/next", nil)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var sj runnerproto.SignedJob
		if err := decodeClosed(resp.Body, maxJobBody, &sj); err != nil {
			return nil, err
		}
		return &sj, nil
	}
	return nil, fmt.Errorf("%w: status %d", ErrTransport, resp.StatusCode)
}

// FetchValue implements Transport.
func (t *HTTPTransport) FetchValue(ctx context.Context, jobID string) (runnerproto.ValueEnvelope, error) {
	body, err := json.Marshal(runnerproto.ValueRequest{JobID: jobID})
	if err != nil {
		return runnerproto.ValueEnvelope{}, ErrTransport
	}
	resp, cancel, err := t.do(ctx, requestTimeout, http.MethodPost, "/runners/jobs/value", body)
	if err != nil {
		return runnerproto.ValueEnvelope{}, err
	}
	defer cancel()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return runnerproto.ValueEnvelope{}, statusErr(resp.StatusCode)
	}
	var env runnerproto.ValueEnvelope
	if err := decodeClosed(resp.Body, maxEnvBody, &env); err != nil {
		return runnerproto.ValueEnvelope{}, err
	}
	return env, nil
}

// SendResult implements Transport.
func (t *HTTPTransport) SendResult(ctx context.Context, jobID string, r runnerproto.Result) error {
	if !jobIDRe.MatchString(jobID) {
		return ErrRefused
	}
	body, err := json.Marshal(r)
	if err != nil {
		return ErrTransport
	}
	resp, cancel, err := t.do(ctx, requestTimeout, http.MethodPost, "/runners/jobs/"+jobID+"/result", body)
	if err != nil {
		return err
	}
	defer cancel()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return statusErr(resp.StatusCode)
}
