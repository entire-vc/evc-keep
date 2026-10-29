package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// enrollTokenResponse mirrors internal/enrolltoken's WireJSON shape. keep
// defines its own copy rather than importing internal/enrolltoken — the
// CLI and the server share only the JSON contract on the wire, per
// keep-api-surface's import boundary (cmd/keep never imports pkg/secret or
// anything that could carry it).
type enrollTokenResponse struct {
	TokenID      string    `json:"token_id"`
	Token        string    `json:"token"`
	Last4        string    `json:"last4"`
	OrgID        string    `json:"org_id"`
	Host         string    `json:"host"`
	PolicySHA256 string    `json:"policy_sha256"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type revokeResponse struct {
	OK        bool   `json:"ok"`
	RequestID string `json:"request_id"`
}

func adminToken() (string, error) {
	t := os.Getenv("KEEP_ADMIN_TOKEN")
	if t == "" {
		return "", fmt.Errorf("KEEP_ADMIN_TOKEN is required (an org admin bearer token — never pass it as a flag)")
	}
	return t, nil
}

func warnIfInsecure(insecureSkipVerify bool) {
	if insecureSkipVerify {
		fmt.Fprintln(os.Stderr, "keep runner: WARNING -insecure-skip-verify is set — the admin bearer token, and anything the request carries, is exposed to anyone on the network path to -server. Use only against a trusted loopback/CI address.")
	}
}

// requireHTTPSServer refuses a non-https -server value before the admin
// bearer token or an enrollment token ever leaves this process: an http://
// URL puts both the Authorization header and the request body (which for
// enroll-token carries the future one-time token) on the wire in the clear
// for anyone on the network path, not just an intentionally-insecure TLS
// peer the way -insecure-skip-verify is (card's leak-review finding: plain
// http was accepted silently).
func requireHTTPSServer(server string) error {
	if !strings.HasPrefix(server, "https://") {
		return fmt.Errorf("-server must be an https:// URL")
	}
	return nil
}

// loadServerCAPool reads a PEM-encoded CA bundle from path, for operators
// who want this command to trust exactly that CA for Keep Server's listener
// certificate instead of the OS trust store — e.g. an internal PKI, or
// Keep Server run with its own self-signed default (leak-review finding:
// the only pinning option before this was -insecure-skip-verify, which
// trusts everything). An empty path returns a nil pool, meaning "use the
// system default," same as before this flag existed.
func loadServerCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied path, same trust level as any CLI config flag
	if err != nil {
		return nil, errors.New("reading -server-ca: file could not be read")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("-server-ca: no PEM certificate found in the file")
	}
	return pool, nil
}

func httpClient(insecureSkipVerify bool, serverCAPool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify, RootCAs: serverCAPool}, //nolint:gosec // G402: opt-in flag, test/CI only
		},
		// A redirect Keep Server never legitimately sends would otherwise be
		// followed automatically, resending the Authorization header and
		// this request's body (an enrollment token, on the enroll-token
		// path) to whatever origin the response named — including a
		// same-host https-to-http downgrade, which net/http's default
		// redirect policy does not treat as a reason to drop the header.
		// Returning the 3xx response as-is instead means the caller's own
		// status-code check below rejects it without ever making a second
		// request.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func runRunnerEnrollToken(args []string) int {
	fs := flag.NewFlagSet("runner enroll-token", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", "", "expected hostname of the enrolling runner")
	policyPath := fs.String("policy", "", "path to the host policy file to bind this token to")
	server := fs.String("server", os.Getenv("KEEP_SERVER"), "Keep Server's runner (mTLS) listener base URL")
	ttl := fs.Duration("ttl", 15*time.Minute, "token TTL, at most 15m")
	uidShared := fs.Bool("uid-shared", false, "assert whether agents and consumers share a host UID; specify explicitly for trusted enrollment")
	environment := fs.String("environment", "", "optional host label: development, staging or production")
	platform := fs.String("platform", "", "optional host label: linux or darwin")
	insecureSkipVerify := fs.Bool("insecure-skip-verify", false, "skip verifying the server's listener TLS certificate (test/CI only, never production)")
	serverCA := fs.String("server-ca", os.Getenv("KEEP_SERVER_CA"), "path to a PEM CA bundle to trust for -server's TLS certificate, instead of the system trust store")
	if err := fs.Parse(args); err != nil {
		return flagParseFailed(fs.Name(), err, os.Stderr)
	}
	if *host == "" || *policyPath == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "keep runner enroll-token: -host, -policy and -server (or KEEP_SERVER) are required")
		return 2
	}
	uidSharedSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "uid-shared" {
			uidSharedSet = true
		}
	})
	if !uidSharedSet && (*environment != "" || *platform != "") {
		fmt.Fprintln(os.Stderr, "keep runner enroll-token: -uid-shared must be set when host labels are supplied")
		return 2
	}
	labels := map[string]string{}
	if *environment != "" {
		labels["environment"] = *environment
	}
	if *platform != "" {
		labels["platform"] = *platform
	}
	if err := requireHTTPSServer(*server); err != nil {
		fmt.Fprintf(os.Stderr, "keep runner enroll-token: %v\n", err)
		return 2
	}
	warnIfInsecure(*insecureSkipVerify)
	serverCAPool, err := loadServerCAPool(*serverCA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep runner enroll-token: %v\n", err)
		return 2
	}
	token, err := adminToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep runner enroll-token: %v\n", err)
		return 2
	}

	policyBytes, err := os.ReadFile(*policyPath) //nolint:gosec // G304: operator-supplied path
	if err != nil {
		fmt.Fprintln(os.Stderr, "keep runner enroll-token: reading policy file: could not be read")
		return 1
	}
	sum := sha256.Sum256(policyBytes)
	policySHA256 := hex.EncodeToString(sum[:])

	issueRequest := map[string]any{"host": *host, "policy_sha256": policySHA256, "ttl_seconds": int64(ttl.Seconds())}
	if uidSharedSet {
		issueRequest["host_attrs"] = map[string]any{"uid_shared": *uidShared, "labels": labels}
	}
	reqBody, err := json.Marshal(issueRequest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep runner enroll-token: %v\n", err)
		return 1
	}

	url := strings.TrimRight(*server, "/") + "/runners/enroll-tokens"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBody)) //nolint:gosec // G704: -server is an operator-supplied CLI flag naming Keep Server's own address, the same trust level as any CLI client's server flag
	if err != nil {
		fmt.Fprintln(os.Stderr, "keep runner enroll-token: -server is not a valid URL")
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient(*insecureSkipVerify, serverCAPool).Do(req) //nolint:gosec // G704: see NewRequest above
	if err != nil {
		fmt.Fprintln(os.Stderr, "keep runner enroll-token: request failed: "+requestFailureKind(err))
		return 1
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		printAPIError(os.Stderr, resp.Body)
		return 1
	}

	var res enrollTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		fmt.Fprintf(os.Stderr, "keep runner enroll-token: decoding response: %v\n", err)
		return 1
	}

	// The token itself goes to stdout alone, so it can be piped straight
	// into `keep-runner enroll` (which reads it from stdin) without
	// ever landing in a shell history or a flag. Everything else — none
	// of it secret — goes to stderr.
	// Keep this pipe value unfiltered: the metadata JSON escaping policy
	// excludes enrollment credentials (security contract section 4.3).
	// https://mesh.entire.host/d/ca015950-a138-416f-accd-7915631eaab0
	fmt.Println(res.Token)
	fmt.Fprintf(os.Stderr, "issued token %s (…%s) for host %q, expires %s\n",
		sanitizeText(res.TokenID, maxRequestIDLen), sanitizeText(res.Last4, 8), sanitizeText(res.Host, maxErrTextRunes), res.ExpiresAt.Format(time.RFC3339))
	return 0
}

func runRunnerRevoke(args []string) int {
	fs := flag.NewFlagSet("runner revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", os.Getenv("KEEP_SERVER"), "Keep Server's runner (mTLS) listener base URL")
	insecureSkipVerify := fs.Bool("insecure-skip-verify", false, "skip verifying the server's listener TLS certificate (test/CI only, never production)")
	serverCA := fs.String("server-ca", os.Getenv("KEEP_SERVER_CA"), "path to a PEM CA bundle to trust for -server's TLS certificate, instead of the system trust store")
	if err := fs.Parse(args); err != nil {
		return flagParseFailed(fs.Name(), err, os.Stderr)
	}
	runnerID := fs.Arg(0)
	if runnerID == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "keep runner revoke: usage: keep runner revoke -server <url> <runner_id>")
		return 2
	}
	if _, err := uuid.Parse(runnerID); err != nil {
		// The argument is never echoed back: an operator who pastes an
		// enrollment token or another secret-shaped value into this
		// position by mistake must not see it printed a second time.
		fmt.Fprintln(os.Stderr, "keep runner revoke: argument is not a runner id (expected a UUID)")
		return 2
	}
	if err := requireHTTPSServer(*server); err != nil {
		fmt.Fprintf(os.Stderr, "keep runner revoke: %v\n", err)
		return 2
	}
	warnIfInsecure(*insecureSkipVerify)
	serverCAPool, err := loadServerCAPool(*serverCA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep runner revoke: %v\n", err)
		return 2
	}
	token, err := adminToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep runner revoke: %v\n", err)
		return 2
	}

	url := strings.TrimRight(*server, "/") + "/runners/" + runnerID + "/revoke"
	req, err := http.NewRequest(http.MethodPost, url, nil) //nolint:gosec // G704: -server is an operator-supplied CLI flag naming Keep Server's own address, the same trust level as any CLI client's server flag
	if err != nil {
		fmt.Fprintln(os.Stderr, "keep runner revoke: -server or runner id is not a valid URL part")
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient(*insecureSkipVerify, serverCAPool).Do(req) //nolint:gosec // G704: see NewRequest above
	if err != nil {
		fmt.Fprintln(os.Stderr, "keep runner revoke: request failed: "+requestFailureKind(err))
		return 1
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		printAPIError(os.Stderr, resp.Body)
		return 1
	}
	var res revokeResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		fmt.Fprintf(os.Stderr, "keep runner revoke: decoding response: %v\n", err)
		return 1
	}
	fmt.Printf("revoked runner_id=%s ok=%t request_id=%s\n", runnerID, res.OK, safeRequestID(res.RequestID))
	return 0
}

type apperrBody struct {
	ErrorClass string `json:"error_class"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
}

func printAPIError(w io.Writer, body io.Reader) {
	var e apperrBody
	if err := json.NewDecoder(body).Decode(&e); err != nil {
		_, _ = fmt.Fprintln(w, "keep: server rejected the request")
		return
	}
	_, _ = fmt.Fprintf(w, "keep: %s: %s (request_id=%s)\n", safeClass(e.ErrorClass), sanitizeText(e.Message, maxErrTextRunes), safeRequestID(e.RequestID))
}
