//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// agentAccount returns the stand's separate "agent" user, if it exists. The
// uid/gid ownership checks need a real second account, so they run only on
// the Linux stand; anywhere else they are reported as SKIP, never as PASS.
func agentAccount() (uid, gid int64, ok bool) {
	u, err := user.Lookup("agent")
	if err != nil || runtime.GOOS != "linux" {
		return 0, 0, false
	}
	uid, e1 := strconv.ParseInt(u.Uid, 10, 64)
	gid, e2 := strconv.ParseInt(u.Gid, 10, 64)
	return uid, gid, e1 == nil && e2 == nil
}

// human plays the person in a browser: opens the link, types the value.
// Only the completion metadata the page shows comes back.
func human(t *testing.T, url, value string) (version, fp string, diag string) {
	t.Helper()
	in, err := json.Marshal(map[string]string{"url": url, "plaintext": value})
	if err != nil {
		t.Fatal("encode browser fixture")
	}
	defer clear(in)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "human.mjs") //nolint:gosec // G204: fixed script
	cmd.Stdin = bytes.NewReader(in)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		reason := browserReason(errOut.String())
		if reason == "human browser failed" && !canary.Of(value).In(errOut.String()) && len(errOut.String()) < 600 {
			reason += ": " + errOut.String() // the value is not in it: checked just above
		}
		t.Fatal(reason)
	}
	var res struct{ Version, Fingerprint string }
	if json.Unmarshal(out.Bytes(), &res) != nil || res.Version == "" || res.Fingerprint == "" {
		t.Fatal("human browser: no completion metadata")
	}
	return res.Version, res.Fingerprint, out.String() + errOut.String()
}

// browserReason picks the fixed assertion text of human.mjs out of stderr.
func browserReason(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "human browser:"); i >= 0 {
			return line[i:]
		}
	}
	return "human browser failed"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

type deployAnswer struct {
	OK          bool   `json:"ok"`
	RequestID   string `json:"request_id"`
	Fingerprint string `json:"fingerprint"`
	Version     string `json:"version"`
	ErrorClass  string `json:"error_class"`
	Message     string `json:"message"`
}

func (w *world) deploy(target, requestID string, extra ...string) (int, string, string, deployAnswer) {
	w.t.Helper()
	args := []string{"deploy", secretName, "--runner", w.runnerID, "--kind", "env-file", "--target", target,
		"--field", secretName, "--uid", strconv.Itoa(os.Getuid()), "--gid", strconv.Itoa(os.Getgid()), "--request-id", requestID, "--wait", "60s", "--json"}
	code, so, se := w.agentKeep(append(args, extra...)...)
	var a deployAnswer
	_ = json.Unmarshal([]byte(so), &a)
	return code, so, se, a
}

func TestW2InputLinkToRunnerPlacement(t *testing.T) {
	if testing.Short() {
		t.Skip("builds three binaries, starts a server and a browser")
	}
	agentUID, agentGID, haveAgent := agentAccount()
	w := newWorld(t, func(dir string) map[string]any {
		uids, gids := []int64{}, []int64{}
		if haveAgent {
			uids, gids = []int64{agentUID}, []int64{agentGID}
		}
		return map[string]any{"version": 1, "agent_uids": uids, "agent_gids": gids, "max_deploys_per_hour": 100,
			"targets": []map[string]any{{"kind": "env-file", "path_prefixes": []string{dir}, "fields": []string{secretName}}}}
	})
	c := canary.New()
	value := c.Value(1)
	if !c.In("xx"+value+"yy") || !c.In(base64Of("a"+value)) {
		t.Fatal("canary detector is blind (positive control)")
	}

	// 1. The agent asks for an input link.
	code, linkOut, linkErr := w.agentKeep("input-link", secretName)
	if code != 0 {
		t.Fatalf("keep input-link exit %d: %s", code, linkErr)
	}
	var link struct {
		URL       string `json:"url"`
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal([]byte(linkOut), &link) != nil || link.URL == "" || !strings.HasPrefix(link.URL, w.publicURL+"/input/") {
		t.Fatalf("input-link answer: %q", linkErr)
	}

	// 2. The human opens it and types the value in a real browser.
	pageVersion, pageFP, humanDiag := human(t, link.URL, value)

	// 3. The agent deploys the secret.
	file := filepath.Join(w.hostDir, ".env")
	req := "w2-ok-" + uuid.NewString()[:8]
	code, depOut, depErr, got := w.deploy(file, req)
	if code != 0 || !got.OK {
		t.Fatalf("keep deploy exit %d\nstdout: %s\nstderr: %s\nrunner: %s", code, depOut, depErr, w.runnerOut.String())
	}

	// 4. The host side, as the root of the stand, never as the agent: the line
	// is there and the three fingerprints agree.
	raw, err := os.ReadFile(file) //nolint:gosec // G304: stand-owned path
	if err != nil {
		t.Fatal("runner did not create the target file")
	}
	if !strings.Contains(string(raw), secretName+"=") || !c.In(string(raw)) {
		t.Fatal("target file does not carry the placed line (positive control for the canary)")
	}
	// The placed line is the typed value, byte for byte.
	if fileValue := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), secretName+"=")); fileValue != value {
		t.Error("the value on the host differs from the one typed in the browser")
	}
	var catalogFP string
	if err := w.pool.QueryRow(context.Background(), `SELECT fingerprint FROM secret_versions WHERE secret_id=$1 ORDER BY created_at DESC LIMIT 1`, w.secretID).Scan(&catalogFP); err != nil {
		t.Fatal("read catalog fingerprint")
	}
	// The fingerprint the page showed, the catalog holds and the deploy answer
	// carries is one and the same. (Computing it from the canary in the test
	// needs internal/builtin, which depguard zone-internals keeps out of
	// test/e2e: reported to the lead in the MR, not weakened here.)
	for name, fp := range map[string]string{"catalog": catalogFP, "deploy answer": got.Fingerprint} {
		if fp == "" || fp != pageFP {
			t.Errorf("%s fingerprint %q differs from the page's %q", name, fp, pageFP)
		}
	}
	if got.Version == "" || got.Version != pageVersion {
		t.Errorf("deploy version %q differs from the page's %q", got.Version, pageVersion)
	}

	// 5. The agent's side is clean: nothing the agent could ever read carries
	// the value, in any of the six encodings.
	surfaces := map[string]string{
		"input-link stdout": linkOut, "input-link stderr": linkErr, "deploy stdout": depOut, "deploy stderr": depErr,
		"status answer": w.statusAnswer(got.RequestID), "server output": w.serverOut.String(), "runner output": w.runnerOut.String(),
		"enroll output": w.enrollOut.String(), "journal": w.auditText(), "browser diagnostics": humanDiag,
	}
	for name, s := range surfaces {
		if c.In(s) {
			t.Errorf("value canary found in %s", name)
		}
		if s == "" && (name == "server output" || name == "journal") {
			t.Errorf("%s is empty: the leak search had nothing to look at", name)
		}
	}

	// 6. Forbidden targets: a refusal that names the reason, file untouched.
	t.Run("forbidden targets", func(t *testing.T) {
		outsideDir := filepath.Join(filepath.Dir(w.hostDir), "elsewhere")
		if err := os.Mkdir(outsideDir, 0o700); err != nil {
			t.Fatal("create outside directory")
		}
		linkDir := filepath.Join(w.hostDir, "via-link")
		if err := os.Symlink(outsideDir, linkDir); err != nil {
			t.Fatal("create symlink")
		}
		cases := []struct {
			name, target, touched string
			wantClass             string
		}{
			{"network url", "https://example.invalid/hook", "", "invalid_argument"},
			{"symlink in the middle", filepath.Join(linkDir, "x.env"), filepath.Join(outsideDir, "x.env"), "policy_denied"},
			{"outside host policy prefixes", filepath.Join(outsideDir, "y.env"), filepath.Join(outsideDir, "y.env"), "policy_denied"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, so, se, a := w.deploy(tc.target, "w2-deny-"+uuid.NewString()[:8])
				t.Logf("exit %d\nstdout: %s\nstderr: %s", code, so, se)
				if code == 0 || a.OK {
					t.Fatalf("forbidden target accepted: %s", so)
				}
				// The class is the closed reason the product reports: in the
				// answer for a runner refusal, on stderr for a refusal before any job.
				if a.ErrorClass != tc.wantClass && !strings.Contains(se, "keep: "+tc.wantClass+":") {
					t.Errorf("want error_class %s, got %q / %q", tc.wantClass, a.ErrorClass, firstLine(se))
				}
				if tc.touched != "" {
					if _, err := os.Stat(tc.touched); err == nil {
						t.Errorf("file outside the target was created: %s", tc.touched)
					}
				}
				if c.In(so + se) {
					t.Error("value canary in a refusal")
				}
			})
		}
		// A path the agent account can read: a directory 0755 and a file the
		// request asks to be 0644, or owned by the agent itself.
		for _, tc := range []struct {
			name  string
			extra []string
		}{
			{"file mode 0644 in a 0755 directory", []string{"--mode", "0644"}},
			{"file owned by the agent", []string{"--uid", strconv.FormatInt(agentUID, 10), "--gid", strconv.FormatInt(agentGID, 10)}},
		} {
			t.Run("agent-readable path: "+tc.name, func(t *testing.T) {
				if !haveAgent {
					t.Skip("needs the Linux stand with a separate user \"agent\"; SKIP is not PASS")
				}
				open := filepath.Join(w.hostDir, "open-"+uuid.NewString()[:6])
				if err := os.Mkdir(open, 0o755); err != nil { //nolint:gosec // G301: the point of the case
					t.Fatal("create readable directory")
				}
				target := filepath.Join(open, "z.env")
				code, so, se, a := w.deploy(target, "w2-deny-"+uuid.NewString()[:8], tc.extra...)
				t.Logf("exit %d\nstdout: %s\nstderr: %s", code, so, se)
				if code == 0 || a.OK {
					t.Fatalf("path readable by the agent accepted: %s", so)
				}
				if a.ErrorClass != "policy_denied" && !strings.Contains(se, "keep: policy_denied:") {
					t.Errorf("want error_class policy_denied, got %q / %q", a.ErrorClass, firstLine(se))
				}
				if _, err := os.Stat(target); err == nil {
					t.Error("a file the agent can read was created")
				}
			})
		}
	})
}
