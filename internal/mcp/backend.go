package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/version"
)

var serverVersion = version.String()

const maxResponseBytes = 1 << 20

// Config says where the REST API is and who is calling it. Token is the
// caller's own bearer token; it is sent to BaseURL only and appears in no
// output.
type Config struct {
	BaseURL string
	Org     string
	Token   string
	// HTTP overrides the client; tests only. Redirects are refused either way.
	HTTP *http.Client
}

// apiError is the server's error body (threat model §4.3, Error row).
type apiError struct {
	Status     int    `json:"-"`
	ErrorClass string `json:"error_class"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
}

// transportError is a failure before any server answer; it names a class of
// failure and nothing about the request.
type transportError struct{ kind string }

func (e *transportError) Error() string { return e.kind }

type backend struct {
	base  string
	org   string
	token string
	http  *http.Client
}

func newBackend(cfg Config) (*backend, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("mcp: base URL is invalid")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return nil, errors.New("mcp: base URL must use https (plain http only against a loopback host)")
	}
	if cfg.Org == "" || cfg.Token == "" {
		return nil, errors.New("mcp: organization and token are required")
	}
	c := cfg.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	cc := *c
	// The bearer token goes only to the host named in BaseURL.
	cc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &backend{base: strings.TrimRight(cfg.BaseURL, "/"), org: cfg.Org, token: cfg.Token, http: &cc}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// do sends one request and returns the status and raw body of a success, or
// an *apiError / *transportError.
func (b *backend) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, &transportError{"request could not be built"}
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+path, rd)
	if err != nil {
		return 0, nil, &transportError{"request could not be built"}
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.http.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return 0, nil, &transportError{"timeout"}
		}
		return 0, nil, &transportError{"server unreachable"}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return 0, nil, &transportError{"response unreadable"}
	}
	if resp.StatusCode >= http.StatusBadRequest {
		var ae apiError
		if decodeStrict(raw, &ae) != nil {
			return 0, nil, &transportError{"server answered with an unreadable error"}
		}
		ae.Status = resp.StatusCode
		return 0, nil, &ae
	}
	if resp.StatusCode >= 300 {
		return 0, nil, &transportError{"unexpected redirect"}
	}
	return resp.StatusCode, raw, nil
}

func (b *backend) orgPath(rest string) string { return "/orgs/" + url.PathEscape(b.org) + rest }

func (e *apiError) Error() string { return e.ErrorClass }
