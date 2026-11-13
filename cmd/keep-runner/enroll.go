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
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/runner"
)

// defaultCredDir is where an enrolled runner's credential lives. Overridable
// with -cred-dir for tests and non-default installs; production deploys
// under a dedicated OS user (see ADR-001 §3.2) whose home this normally is.
const defaultCredDir = "/etc/keep/runner"

// maxEnrollTokenBytes caps the raw stdin input accepted as the enrollment token.
const maxEnrollTokenBytes = 4096

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
	pem, err := readServerCAFile(path, maxServerCABytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("-server-ca: no PEM certificate found in the file")
	}
	return pool, nil
}

// enrollTimeout bounds the whole enrollment request; a variable only so
// tests can shorten it.
var enrollTimeout = 30 * time.Second

// requestFailureKind names why a request failed without printing err: a
// *url.Error carries the full request URL and the dial error carries the
// host, either of which may hold a credential pasted into -server.
func requestFailureKind(err error) string {
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCert x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &unknownAuthority) || errors.As(err, &invalidCert) || errors.As(err, &hostnameErr) {
		return "TLS certificate verification failed"
	}
	if errors.As(err, &recordHeader) {
		return "TLS handshake failed"
	}
	// A TLS alert from the peer (handshake failure, certificate required, ...)
	// arrives as a net.OpError whose Op crypto/tls fixes to "remote error".
	var tlsAlert tls.AlertError
	var opErr *net.OpError
	if errors.As(err, &tlsAlert) || (errors.As(err, &opErr) && opErr.Op == "remote error") {
		return "TLS handshake failed"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "could not reach the server"
}

func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	host := fs.String("host", "", "this host's name, must match what the enrollment token was issued for")
	server := fs.String("server", os.Getenv("KEEP_SERVER"), "Keep Server's runner (mTLS) listener base URL, e.g. https://keep.example:8443")
	policyPath := fs.String("policy", "", "path to the local host policy file, must match the SHA-256 the token was bound to")
	credDir := fs.String("cred-dir", defaultCredDir, "directory to write the enrollment credential to")
	insecureSkipVerify := fs.Bool("insecure-skip-verify", false, "skip verifying the server's listener TLS certificate (test/CI only, never production)")
	serverCA := fs.String("server-ca", os.Getenv("KEEP_SERVER_CA"), "path to a PEM CA bundle to trust for -server's TLS certificate, instead of the system trust store")
	if rc, ok := parseFlagsSafe(fs, "enroll", args); !ok {
		return rc
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
	// Read one byte past the cap: a longer input is refused outright, never
	// truncated into a shorter (wrong) token. No input byte is echoed.
	tokenBytes, err := io.ReadAll(io.LimitReader(os.Stdin, maxEnrollTokenBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: reading token from stdin: %v\n", err)
		return 1
	}
	if len(tokenBytes) > maxEnrollTokenBytes {
		fmt.Fprintf(os.Stderr, "keep-runner enroll: stdin input exceeds %d bytes; refusing to truncate the token\n", maxEnrollTokenBytes)
		return 2
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		fmt.Fprintln(os.Stderr, "keep-runner enroll: enrollment token must be provided on stdin")
		return 2
	}

	policyBytes, err := readPolicyFile(*policyPath)
	if err != nil {
		// Only a static line is printed: the path and file bytes never appear.
		fmt.Fprintln(os.Stderr, "keep-runner enroll: reading policy file failed: missing or unreadable")
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
		Timeout: enrollTimeout,
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
		// err is a *url.Error quoting the full URL (userinfo, path, query)
		// and the dial error quotes the host: only a static class is printed.
		fmt.Fprintln(os.Stderr, "keep-runner enroll: request failed: "+requestFailureKind(err))
		return 1
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		printAPIError(resp.Body)
		return 1
	}

	var res runnerEnrollResponse
	if err := decodeBounded(resp.Body, &res); err != nil {
		// The decoder's text can quote the offending field of the server's
		// answer, so only a static line is printed.
		fmt.Fprintln(os.Stderr, "keep-runner enroll: decoding response: server answer is not valid")
		return 1
	}

	// Everything in the answer is server text: it is checked before anything
	// is written, and a refusal is a static line that reflects none of it.
	if err := validateEnrollResponse(res); err != nil {
		fmt.Fprintln(os.Stderr, "keep-runner enroll: server answer is not valid: "+err.Error())
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
		// err quotes the -cred-dir path; only a static line is printed.
		fmt.Fprintln(os.Stderr, "keep-runner enroll: saving credential failed: -cred-dir is not writable")
		return 1
	}

	// not_after is deliberately not printed: even a valid RFC3339 value
	// carries arbitrary digits chosen by the server. runner_id is printed
	// only because validateEnrollResponse pinned it to a canonical UUID.
	fmt.Printf("enrolled: runner_id=%s\n", res.RunnerID)
	return 0
}

// canonicalUUID reports whether s is exactly the canonical lowercase
// 8-4-4-4-12 form, nothing else (no braces, urn prefix, padding, uppercase).
func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && len(s) == 36 && u.String() == s
}

// signKeyIDRe is the format internal/builtin/orgpki mints.
var signKeyIDRe = regexp.MustCompile(`^orgsign_[0-9a-f]{16}$`)

// validateEnrollResponse checks the server's answer before any of it is
// saved. Its errors are static: no part of the answer is reflected.
func validateEnrollResponse(res runnerEnrollResponse) error {
	if !signKeyIDRe.MatchString(res.SignKeyID) {
		return errors.New("sign_key_id has an unexpected form")
	}
	if !canonicalUUID(res.RunnerID) {
		return errors.New("runner_id is not a valid UUID")
	}
	// run.go takes the runner's identity from the certificate's common
	// name, so the id printed here must be that same identity.
	cert, err := x509.ParseCertificate(res.Certificate)
	if err != nil {
		return errors.New("certificate cannot be parsed")
	}
	if cert.Subject.CommonName != res.RunnerID {
		return errors.New("runner_id does not match the certificate")
	}
	return nil
}

// printAPIError reads and prints the {error_class, message, request_id}
// body every Keep Server error takes — never the raw response body, which
// is not a contract this binary should print verbatim.
func printAPIError(body io.Reader) {
	var e apperrBody
	if err := decodeBounded(body, &e); err != nil {
		fmt.Fprintln(os.Stderr, "keep-runner enroll: server rejected the request")
		return
	}
	// The server's message is never printed; class and request id pass only
	// if they have the shape the server itself produces (threat model 4.3).
	fmt.Fprintf(os.Stderr, "keep-runner enroll: %s (request_id=%s)\n", safeClass(e.ErrorClass), safeRequestID(e.RequestID))
}

// maxEnrollResponseBytes caps what enroll reads from the server: a hostile
// or broken server must not be able to make the process buffer an unbounded
// answer.
const maxEnrollResponseBytes = 1 << 20

var errResponseTooLarge = errors.New("response body exceeds limit")

var errTrailingData = errors.New("response body is not a single JSON document")

// decodeBounded reads at most maxEnrollResponseBytes of r and decodes it as
// JSON into v. Longer input, or anything after the first JSON value other
// than whitespace, is refused with a static error.
func decodeBounded(r io.Reader, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, maxEnrollResponseBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxEnrollResponseBytes {
		return errResponseTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Exactly one document: a second value or trailing garbage is refused
	// before any caller acts on the first. Trailing whitespace is io.EOF.
	if _, err := dec.Token(); err != io.EOF {
		return errTrailingData
	}
	return nil
}

const unexpectedValue = "(unexpected value)"

// safeClass passes an error class through only if it is in the closed set.
func safeClass(c string) string {
	for _, k := range apperr.Classes() {
		if string(k) == c {
			return c
		}
	}
	return unexpectedValue
}

// safeRequestID passes a request id through only if internal/reqid accepts it.
func safeRequestID(id string) string {
	if id != "" && !reqid.Valid(id) {
		return unexpectedValue
	}
	return id
}
