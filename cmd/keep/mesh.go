package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// meshUninstallResult is the closed answer of
// DELETE /orgs/{org_id}/mesh/installations/{workspace_id} (threat model §4.3).
// Only these fields are decoded, so anything else the server sends is dropped.
type meshUninstallResult struct {
	WorkspaceID string `json:"workspace_id"`
	Erased      int    `json:"erased"`
	RequestID   string `json:"request_id"`
}

func runMeshSubcommand(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 || args[0] != "uninstall" {
		_, _ = fmt.Fprintln(stderr, `keep mesh: only "uninstall" is supported`)
		return 2
	}
	ws, rest, err := splitPositional(args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "keep mesh uninstall: a workspace id is required")
		return 2
	}
	// The id is checked before anything else, and never echoed if it is not
	// one: a credential pasted into the wrong place must not be printed.
	id, err := uuid.Parse(ws)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "keep mesh uninstall: the workspace id is not a UUID")
		return 2
	}
	fs := flag.NewFlagSet("mesh uninstall", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(rest); err != nil {
		return flagParseFailed(fs.Name(), err, stderr)
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "keep mesh uninstall: %d unexpected argument(s)\n", fs.NArg())
		return 2
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	if !*yes && !confirmUninstall(id.String(), stdin, stderr) {
		_, _ = fmt.Fprintln(stderr, "keep mesh uninstall: not confirmed; nothing was removed")
		return 1
	}
	if err := cmdMeshUninstall(c, id.String(), g.jsonOut, stdout); err != nil {
		return reportErr(stderr, err)
	}
	return 0
}

// confirmUninstall asks on stderr and accepts only "y" or "yes" on stdin.
func confirmUninstall(ws string, stdin io.Reader, stderr io.Writer) bool {
	_, _ = fmt.Fprintf(stderr, "Remove the Mesh installation of workspace %s and erase every secret it stored? This cannot be undone. [y/N] ", ws)
	line, _ := bufio.NewReader(io.LimitReader(stdin, 64)).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// cmdMeshUninstall removes the installation and prints the closed answer. A
// workspace id or request id outside its shape is shown as "(unexpected
// value)": a misbehaving server cannot push anything else through.
func cmdMeshUninstall(c *client, ws string, jsonOut bool, w io.Writer) error {
	body, err := c.do(http.MethodDelete, "/mesh/installations/"+url.PathEscape(ws), nil, nil)
	if err != nil {
		return err
	}
	var res meshUninstallResult
	if err := json.Unmarshal(body, &res); err != nil {
		return fmt.Errorf("parse server response: %w", err)
	}
	if res.WorkspaceID != ws {
		res.WorkspaceID = "(unexpected value)"
	}
	if !auditRequestID.MatchString(res.RequestID) {
		res.RequestID = "(unexpected value)"
	}
	if res.Erased < 0 {
		res.Erased = 0
	}
	if jsonOut {
		return writeJSONValue(w, res)
	}
	tw := newTabwriter(w)
	_, _ = fmt.Fprintf(tw, "workspace_id:\t%s\n", res.WorkspaceID)
	_, _ = fmt.Fprintf(tw, "erased:\t%d\n", res.Erased)
	_, _ = fmt.Fprintf(tw, "request_id:\t%s\n", res.RequestID)
	return tw.Flush()
}
