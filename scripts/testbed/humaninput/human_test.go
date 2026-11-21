// Package humaninput plays the human at the browser on an input link: it
// opens the page the link names, seals a test canary to the page's recipient
// key the way the page's script does (HPKE base mode, X25519/HKDF-SHA256/
// AES-256-GCM, info "keep/intake/v1\x00"+request id) and posts the envelope.
// It prints the version and the fingerprint the server answers with, and
// never the value. The stand has no browser; the page's own script is
// covered by scripts/check-intake-browser.sh.
//
// It is a test file on purpose: HPKE primitives are confined by the linter to
// intake and to tests. The stand runs it as a compiled test binary:
//
//	humaninput -test.run TestHumanEntersTheValue   (KEEP_HUMAN_LINK, KEEP_HUMAN_OUT, optionally KEEP_HUMAN_VALUE_FILE)
package humaninput

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

var (
	reRequest = regexp.MustCompile(`data-request="([^"]+)"`)
	rePublic  = regexp.MustCompile(`data-public="([^"]+)"`)
)

func TestHumanEntersTheValue(t *testing.T) {
	link, out := os.Getenv("KEEP_HUMAN_LINK"), os.Getenv("KEEP_HUMAN_OUT")
	if link == "" || out == "" {
		t.Skip("a helper of the rotation testbed; run by scripts/testbed/rotation.sh")
	}
	if err := run([]string{link, out}); err != nil {
		t.Fatalf("humaninput: %v", err)
	}
}

func run(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: humaninput <input link> <value file to write the canary to>")
	}
	link, valueFile := args[0], args[1]
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	page, err := get(client, link)
	if err != nil {
		return err
	}
	req, pub := reRequest.FindSubmatch(page), rePublic.FindSubmatch(page)
	if req == nil || pub == nil {
		return fmt.Errorf("the page carries no request or recipient key")
	}
	requestID := html.UnescapeString(string(req[1]))
	recipient, err := base64.StdEncoding.DecodeString(html.UnescapeString(string(pub[1])))
	if err != nil || len(recipient) != 32 {
		return fmt.Errorf("recipient key is malformed")
	}
	// The human types a canary of the stand's own, or, for the Mesh stand, the
	// agent key the operator left in KEEP_HUMAN_VALUE_FILE (a file, never an
	// argument or a variable).
	value := canary.New().Value(1)
	if vf := os.Getenv("KEEP_HUMAN_VALUE_FILE"); vf != "" {
		b, rerr := os.ReadFile(vf) //nolint:gosec // G304: a path the stand's script names
		if rerr != nil || len(bytes.TrimSpace(b)) == 0 {
			return fmt.Errorf("the value file is empty or unreadable")
		}
		value = string(bytes.TrimSpace(b))
	}
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	var pk kem.PublicKey
	pk, err = hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(recipient)
	if err != nil {
		return fmt.Errorf("recipient key is not a key")
	}
	sender, err := suite.NewSender(pk, []byte("keep/intake/v1\x00"+requestID))
	if err != nil {
		return err
	}
	enc, sealer, err := sender.Setup(nil)
	if err != nil {
		return err
	}
	ct, err := sealer.Seal([]byte(value), nil)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string][]byte{"enc": enc, "ciphertext": ct})
	resp, err := client.Post( //nolint:gosec // G704: the stand's own input link
		link[:indexFragment(link)], "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post failed")
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("input refused: status %d", resp.StatusCode)
	}
	// The stand's operator keeps the canary to scan outputs for it. It is a
	// test value generated here and written once, mode 0600.
	if err := os.WriteFile(valueFile, //nolint:gosec // G703: a path the stand's script names
		[]byte(value), 0o600); err != nil {
		return err
	}
	fmt.Println(string(bytes.TrimSpace(out)))
	return nil
}

func indexFragment(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' {
			return i
		}
	}
	return len(s)
}

func get(c *http.Client, link string) ([]byte, error) {
	resp, err := c.Get(link[:indexFragment(link)]) //nolint:gosec // G704: the stand's own input link
	if err != nil {
		return nil, fmt.Errorf("page request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("page status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
