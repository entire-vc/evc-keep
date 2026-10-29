package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/entire-vc/evc-keep/internal/runner"
)

// defaultCredDir is where an enrolled runner's credential lives. Overridable
// with -cred-dir for tests and non-default installs; production deploys
// under a dedicated OS user (see ADR-001 §3.2) whose home this normally is.
const defaultCredDir = "/etc/keep/runner"

// runnerEnrollResponse mirrors internal/api's runnerCertResponse wire shape.
// keep-runner defines its own copy rather than importing internal/api —
// the two binaries share no package, only a JSON contract.
type runnerEnrollResponse struct {
	RunnerID      string    `json:"runner_id"`
	Certificate   []byte    `json:"certificate"`
	CACertificate []byte    `json:"ca_certificate"`
	SignKeyID     string    `json:"sign_key_id"`
	SignPubKey    []byte    `json:"sign_pub_key"`
	NotAfter      time.Time `json:"not_after"`
}

type apperrBody struct {
	ErrorClass string `json:"error_class"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
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
		return nil, fmt.Errorf("reading -server-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("-server-ca: no PEM certificate found in %s", path)
	}
	return pool, nil
}

func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	host := fs.String("host", "", "this host's name, must match what the enrollment token was issued for")
	server := fs.String("server", os.Getenv("KEEP_SERVER"), "Keep Server's runner (mTLS) listener base URL, e.g. https://keep.example:8443")
	policyPath := fs.String("policy", "", "path to the local host policy file, must match the SHA-256 the token was bound to")
	credDir := fs.String("cred-dir", defaultCredDir, "directory to write the enrollment credential to")
	insecureSkipVerify := fs.Bool("insecure-skip-verify", false, "skip verifying the server's listener TLS certificate (test/CI only, never production)")
	serverCA := fs.String("server-ca", os.Getenv("KEEP_SERVER_CA"), "path to a PEM CA bundle to trust for -server's TLS certificate, instead of the system trust store")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *host == "" || *server == "" || *policyPath == "" {
		fmt.Fprintln(os.Stderr, "keep-runner enroll: -host, -server (or KEEP_SERVER) and -policy are required")
		return 2
	}
	if !strings.HasPrefix(*server, "https://") {
		// The enrollment token (read below) and the CSR go in this
		// request's body; an http:// -server would put both on the wire in
		// the clear for anyone on the network path (card's leak-review
		// finding), not just an intentionally-insecure TLS peer the way
		// -insecure-skip-verify is.
		fmt.Fprintln(os.Stderr, "keep-runner enroll: -server must be an https:// URL")
		return 2
	}
	if *insecureSkipVerify {
		fmt.Fprintln(os.Stderr, "keep-runner enroll: WARNING -insecure-skip-verify is set — the enrollment token, and the CA and signing key pinned from this connection, are exposed to anyone on the network path to -server. Use only against a trusted loopback/CI address.")
	}
	// -server-ca is this command's own pinning option: enrollment is the one
	// request that has no organization CA yet to trust anything against
	// (that CA only arrives IN this response), so until now the only
	// alternative to the OS trust store was -insecure-skip-verify, which
	// trusts everything (leak-review finding).
	serverCAPool, err := loadServerCAPool(*serverCA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: %v\n", err)
		return 2
	}

	// The enrollment token is the credential: it never appears as a flag
	// (argv is visible in ps and in an agent's own transcript) and never
	// touches the environment either — only stdin, read once and used.
	tokenBytes, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: reading token from stdin: %v\n", err)
		return 1
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		fmt.Fprintln(os.Stderr, "keep-runner enroll: enrollment token must be provided on stdin")
		return 2
	}

	policyBytes, err := os.ReadFile(*policyPath) //nolint:gosec // G304: operator-supplied path, same trust level as any CLI config flag
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: reading policy file: %v\n", err)
		return 1
	}
	sum := sha256.Sum256(policyBytes)
	policySHA256 := hex.EncodeToString(sum[:])

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: generating key: %v\n", err)
		return 1
	}
	deliveryKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keep-runner enroll: generating delivery key failed")
		return 1
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: *host}, PublicKey: pub}, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: creating CSR: %v\n", err)
		return 1
	}

	reqBody, err := json.Marshal(map[string]any{
		"token": token, "host": *host, "policy_sha256": policySHA256, "csr": csrDER,
		"hpke_public_key": deliveryKey.PublicKey().Bytes(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: %v\n", err)
		return 1
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecureSkipVerify, RootCAs: serverCAPool}, //nolint:gosec // G402: opt-in flag, test/CI only
		},
		// See cmd/keep's own httpClient for why: a redirect must not cause
		// this request's body — the enrollment token and the CSR — to be
		// resent to a different origin, including an https-to-http
		// downgrade on the same host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := strings.TrimRight(*server, "/") + "/runners/enroll"
	resp, err := client.Post(url, "application/json", bytes.NewReader(reqBody)) //nolint:gosec // G704: -server is an operator-supplied CLI flag naming Keep Server's own address, the same trust level as any CLI client's server flag
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: request failed: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		printAPIError(resp.Body)
		return 1
	}

	var res runnerEnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: decoding response: %v\n", err)
		return 1
	}

	cred := runner.Credential{
		Key:         priv,
		DeliveryKey: deliveryKey,
		CertDER:     res.Certificate,
		CACertDER:   res.CACertificate,
		SignKeyID:   res.SignKeyID,
		SignPubKey:  res.SignPubKey,
		Host:        *host,
	}
	if err := runner.Save(*credDir, cred); err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: saving credential: %v\n", err)
		return 1
	}

	fmt.Printf("enrolled: runner_id=%s not_after=%s cred_dir=%s\n", res.RunnerID, res.NotAfter.Format(time.RFC3339), *credDir)
	return 0
}

// printAPIError reads and prints the {error_class, message, request_id}
// body every Keep Server error takes — never the raw response body, which
// is not a contract this binary should print verbatim.
func printAPIError(body io.Reader) {
	var e apperrBody
	if err := json.NewDecoder(body).Decode(&e); err != nil {
		fmt.Fprintln(os.Stderr, "keep-runner enroll: server rejected the request")
		return
	}
	fmt.Fprintf(os.Stderr, "keep-runner enroll: %s: %s (request_id=%s)\n", e.ErrorClass, e.Message, e.RequestID)
}
