package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/entire-vc/evc-keep/internal/mcp"
)

// runMCP serves Keep's MCP tools on stdin/stdout for an agent host. It is the
// same REST client the other commands are: the caller's own token, the same
// server, and no tool that takes or returns a value.
func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := bindGlobalFlags(fs, getenv)
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "keep mcp: invalid arguments")
		return 2
	}
	server := g.server
	if server == "" {
		server = getenv("KEEP_SERVER")
	}
	if server == "" || g.org == "" {
		return reportErr(stderr, errors.New("--server/KEEP_SERVER and --org/KEEP_ORG are required"))
	}
	token, err := resolveToken(getenv, g.tokenFile)
	if err != nil {
		return reportErr(stderr, err)
	}
	srv, err := mcp.New(mcp.Config{BaseURL: server, Org: g.org, Token: token})
	if err != nil {
		// The package's own messages name no URL, org or token.
		return reportErr(stderr, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := srv.Serve(ctx, stdin, stdout); err != nil && ctx.Err() == nil {
		return reportErr(stderr, errors.New("mcp: transport failed"))
	}
	return 0
}
