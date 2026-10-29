package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// redactedValue replaces the Authorization header's own text everywhere the
// CLI might print a request for --debug — the same reasoning
// internal/identity.Token documents for why a token never renders as
// itself: a debug trace is exactly as public as a log line once it lands in
// a terminal someone screenshots or pastes.
const redactedValue = "[REDACTED]"

// apiError is Keep Server's error body (apperr.Body: error_class, message,
// request_id — threat model §4.3's closed field list) plus the HTTP status
// it arrived with. It is returned as an error so command code can branch on
// ErrorClass without parsing a string.
type apiError struct {
	Status     int    `json:"-"`
	ErrorClass string `json:"error_class"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
}

// Error is safe to print on a terminal: the fields come from the server.
func (e *apiError) Error() string {
	class, msg := safeClass(e.ErrorClass), sanitizeText(e.Message, maxErrTextRunes)
	if e.RequestID == "" {
		return fmt.Sprintf("%s: %s", class, msg)
	}
	return fmt.Sprintf("%s: %s (request_id=%s)", class, msg, safeRequestID(e.RequestID))
}

// client is a thin wrapper over net/http for Keep Server's REST API —
// cmd/keep never touches a database or pkg/secret (.golangci.yml's
// secret-value rule denies that import here), so every command's only path
// to the server is through this type.
type client struct {
	baseURL string
	org     string
	token   string
	http    *http.Client
	debug   bool
	stderr  io.Writer
}

func newClient(baseURL, org, token string, debug bool, stderr io.Writer) *client {
	c := &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		org:     org,
		token:   token,
		debug:   debug,
		stderr:  stderr,
	}
	c.http = &http.Client{
		Timeout: 30 * time.Second,
		// Go's net/http keeps the Authorization header on a same-host
		// redirect (only cross-host redirects strip it), so a compromised
		// or misconfigured server could redirect https -> http on the same
		// host and have the bearer token follow it downgraded. Applying
		// requireSecureURL to every redirect target closes that path
		// without needing a custom Authorization-stripping copy of the
		// default policy.
		//
		// Setting CheckRedirect at all replaces net/http's default policy
		// wholesale, including its 10-redirect cap — a self-redirecting
		// server would otherwise be followed until the client Timeout, not
		// a bounded number of hops. Re-add the same cap net/http's own
		// default uses before applying our own check.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return redirectRefusal{fmt.Errorf("stopped after %d redirects", len(via))}
			}
			if err := requireSecureURL(req.URL); err != nil {
				return redirectRefusal{err}
			}
			// net/http would keep Authorization on a redirect to another
			// port or a subdomain of the same host; the token goes only to
			// the host the operator named.
			if req.URL.Host != via[0].URL.Host {
				return redirectRefusal{errors.New("refusing a redirect to a different host")}
			}
			return nil
		},
	}
	return c
}

// requireSecureURL refuses anything but https unless the host is loopback —
// an operator's own dev server on localhost is a reasonable exception, but a
// bearer token going out over a real network link in plaintext is exactly
// the kind of leak this CLI exists to prevent everywhere else. Applied both
// to --server/KEEP_SERVER itself (see globalOpts.newClient) and to every
// redirect this client follows (see CheckRedirect above).
func requireSecureURL(u *url.URL) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return errors.New("must use https (plain http is only allowed against a loopback host)")
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// redactedHeaderDump renders h for a debug trace with every Authorization
// value replaced — never conditionally, never based on what the value looks
// like, so the guarantee holds even for a malformed or already-redacted
// value.
func redactedHeaderDump(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			if strings.EqualFold(k, "Authorization") {
				v = redactedValue
			}
			fmt.Fprintf(&b, "  %s: %s\n", sanitizeText(k, maxErrTextRunes), sanitizeText(v, maxErrTextRunes))
		}
	}
	return b.String()
}

func (c *client) debugf(format string, args ...any) {
	if !c.debug {
		return
	}
	_, _ = fmt.Fprintf(c.stderr, "[debug] "+format+"\n", args...)
}

// do issues one request against /orgs/{org}{path}?query. It returns exactly
// one of: a body on success, an *apiError decoded from the server's error
// body, or a transport-level error — never a mix, so callers can check err
// first and then type-assert for *apiError.
func (c *client) do(method, path string, query url.Values, body any) ([]byte, error) {
	endpoint := c.baseURL + "/orgs/" + url.PathEscape(c.org) + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	_, b, err := c.doEndpoint(method, endpoint, body)
	return b, err
}

// doEndpoint is do for a full endpoint URL; it also returns the HTTP status
// so a caller can tell a pending 202 from a terminal 200.
func (c *client) doEndpoint(method, endpoint string, body any) (int, []byte, error) {

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, errors.New("marshal request body: failed")
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, endpoint, reqBody)
	if err != nil {
		return 0, nil, errors.New("build request: invalid URL")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Only scheme and host (Hostname and port, never userinfo) are traced:
	// the path and query carry the org and scope ids, which can be a
	// credential pasted into the wrong flag.
	c.debugf("%s %s://%s\n%s", method, req.URL.Scheme, req.URL.Host, redactedHeaderDump(req.Header))

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, errors.New("request failed: " + requestFailureKind(err))
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, errors.New("read response: failed")
	}
	c.debugf("-> %d %s", resp.StatusCode, redactedHeaderDump(resp.Header))

	if resp.StatusCode >= http.StatusBadRequest {
		var ae apiError
		if jsonErr := json.Unmarshal(respBody, &ae); jsonErr != nil {
			return 0, nil, fmt.Errorf("server returned status %d with an unparseable body", resp.StatusCode)
		}
		ae.Status = resp.StatusCode
		return 0, nil, &ae
	}
	return resp.StatusCode, respBody, nil
}

// requestFailureKind names why a request failed without printing err: a
// *url.Error carries the full request URL (org id in the path, scope id in
// the query) and the dial error carries the host, any of which may be a
// credential pasted into the wrong flag.
func requestFailureKind(err error) string {
	var rr redirectRefusal
	if errors.As(err, &rr) {
		return "redirect refused: " + rr.err.Error()
	}
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCert x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	if errors.As(err, &unknownAuthority) || errors.As(err, &invalidCert) || errors.As(err, &hostnameErr) {
		// The type is named, its text (which carries the host) is not.
		return "TLS certificate verification failed"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "could not reach the server"
}

// redirectRefusal marks CheckRedirect's own static refusals so they survive
// the url.Error wrapper and can be reported while the URL itself is not.
type redirectRefusal struct{ err error }

func (r redirectRefusal) Error() string { return r.err.Error() }
