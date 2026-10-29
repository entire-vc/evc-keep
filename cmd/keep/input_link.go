package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/entire-vc/evc-keep/internal/intake"
)

func runInputLink(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	name, rest, err := splitPositional(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "keep input-link: a secret name is required")
		return 2
	}
	fs := flag.NewFlagSet("input-link", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	ttl := fs.String("ttl", "30m", "link lifetime")
	ws := fs.String("workspace", "", "workspace context")
	project := fs.String("project", "", "project context")
	if fs.Parse(rest) != nil || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "keep input-link: invalid arguments")
		return 2
	}
	d, err := time.ParseDuration(*ttl)
	if err != nil || d <= 0 || d > 24*time.Hour {
		_, _ = fmt.Fprintln(stderr, "keep input-link: ttl must be positive and at most 24h")
		return 2
	}
	c, err := g.newClient(getenv, stderr)
	if err != nil {
		return reportErr(stderr, err)
	}
	// Issuance returns a one-time capability; disable raw traces and redirects.
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	body, _ := json.Marshal(map[string]string{"secret": name, "ttl": *ttl, "workspace_id": *ws, "project_id": *project})
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/v1/input-links", bytes.NewReader(body))
	if err != nil {
		return reportErr(stderr, errors.New("input-link request failed"))
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return reportErr(stderr, errors.New("input-link request failed"))
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		return reportErr(stderr, errors.New("input-link request rejected"))
	}
	var link intake.Issued
	if json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&link) != nil || link.URL == "" || link.RequestID == "" || link.ExpiresAt.IsZero() {
		return reportErr(stderr, errors.New("invalid input-link response"))
	}
	if writeJSONValue(stdout, link) != nil {
		return reportErr(stderr, errors.New("cannot write input-link result"))
	}
	return 0
}
