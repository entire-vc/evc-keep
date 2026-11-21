// Command consumer is the stand's stand-in for a service that lives on a
// credential: it reads it from its carrier (an environment variable, a JSON
// config, a file or a systemd credential), refuses to start unless
// the credential has the expected shape, and then serves a fixed health
// marker. It never prints, logs or serves the credential, only its length.
//
// With CONSUMER_VERIFY_URL set (the Mesh stand) the credential is also checked
// against that service: a GET carrying it in the X-Agent-Key header (how Mesh takes an agent key) must answer 200,
// at start and again on every health request, so a key that Mesh has revoked
// is a consumer that is not healthy.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// A generated credential is 43 base64url characters; the stand's first value
// is a test canary of 36. Anything shorter or outside the alphabet is not a
// credential this consumer accepts.
var shape = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

// credName is a credential name as the unit gives it: one path element.
var credName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "consumer:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("consumer", flag.ContinueOnError)
	name := fs.String("name", "", "consumer name, used in the health marker")
	source := fs.String("source", "", "env | mcp-config | file | credential")
	key := fs.String("key", "", "variable, dotted key or credential name")
	path := fs.String("path", "", "file for mcp-config and file")
	listen := fs.String("listen", "", "loopback address for the health endpoint; empty serves none")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *source == "" {
		return errors.New("-name and -source are required")
	}
	raw, err := read(*source, *key, *path)
	if err != nil {
		return err
	}
	if !shape.MatchString(raw) {
		return fmt.Errorf("%s: credential is missing or has the wrong shape", *name)
	}
	verifyURL := os.Getenv("CONSUMER_VERIFY_URL")
	if verifyURL != "" {
		if code, verr := verify(verifyURL, raw); verr != nil || code != http.StatusOK {
			return fmt.Errorf("%s: the service refused the credential (status %d)", *name, code)
		}
	}
	fmt.Printf("consumer %s started with a credential of %d bytes\n", *name, len(raw))
	if *listen == "" {
		ready()
		for {
			time.Sleep(time.Hour)
		}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ready()
	body := "consumer-ok:" + *name + "\n"
	refused := "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	reply := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 4096)
			_, _ = c.Read(buf) // the request is not inspected: any request gets the marker
			// The health check is the credential in use: asked of the service
			// again, now, from its carrier.
			if verifyURL != "" {
				cur, rerr := read(*source, *key, *path)
				if code, verr := verify(verifyURL, cur); rerr != nil || verr != nil || code != http.StatusOK {
					_, _ = c.Write([]byte(refused))
					return
				}
			}
			_, _ = c.Write([]byte(reply))
		}()
	}
}

// ready tells systemd (Type=notify) that the service is up. A restart returns
// only after this, so a health check that follows it never races the start.
func ready() {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}
	c, err := net.Dial("unixgram", sock) //nolint:gosec // G704: systemd's own notify socket
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("READY=1"))
}

func read(source, key, path string) (string, error) {
	switch source {
	case "env":
		return os.Getenv(key), nil
	case "file":
		b, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: the stand's own unit names the path
		return strings.TrimSpace(string(b)), err
	case "credential":
		// systemd decrypted it (LoadCredentialEncrypted=) into the unit's own
		// credentials directory; a unit without one has no credential.
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" || !credName.MatchString(key) {
			return "", errors.New("no credentials directory or no credential name")
		}
		b, err := os.ReadFile(filepath.Join(dir, key)) //nolint:gosec // G304: systemd's directory, a checked name
		return strings.TrimSpace(string(b)), err
	case "mcp-config":
		b, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: the stand's own unit names the path
		if err != nil {
			return "", err
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			return "", errors.New("config is not JSON")
		}
		for _, part := range strings.Split(key, ".") {
			m, ok := doc.(map[string]any)
			if !ok {
				return "", errors.New("config key missing")
			}
			doc = m[part]
		}
		s, _ := doc.(string)
		return s, nil
	}
	return "", errors.New("unknown source")
}

// verify asks the service whether the credential works: one GET with it as a
// bearer token. Only the status leaves this function.
func verify(url, credential string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody) //nolint:gosec // G704: the stand's own Mesh, named by the unit
	if err != nil {
		return 0, errors.New("bad verify url")
	}
	req.Header.Set("X-Agent-Key", credential)
	// No redirect is followed: the key must not leave the origin it was meant
	// for, and another origin's 200 is not an answer of Mesh.
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req) //nolint:gosec // G704: the stand's own Mesh
	if err != nil {
		return 0, errors.New("service unreachable")
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
