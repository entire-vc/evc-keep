// Package mcp is Keep's MCP server: a thin stdio front for the REST API. It
// has no storage, no provider and no logic of its own, and it cannot import
// pkg/secret (.golangci.yml, rule secret-value): nothing it returns can be a
// value. Every tool answer is a closed, typed object from threat model §4.3,
// decoded strictly from the server's reply; an unknown field is a broken
// server and nothing of that reply is forwarded.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	protocolVersion = "2025-06-18"
	maxMessageBytes = 1 << 20

	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// integerID is the only request id that is echoed: a plain integer of at most
// 16 digits (so it stays exact as a JSON number), never a string, object,
// array, float or null.
var integerID = regexp.MustCompile(`^(0|-?[1-9][0-9]{0,15})$`)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Server answers MCP requests over one reader/writer pair, one at a time.
type Server struct {
	tools *toolbox
}

// New builds a server that talks to the Keep REST API described by cfg.
func New(cfg Config) (*Server, error) {
	b, err := newBackend(cfg)
	if err != nil {
		return nil, err
	}
	return &Server{tools: newToolbox(b)}, nil
}

// Serve reads newline-delimited JSON-RPC messages from in and writes the
// answers to out until in ends or ctx is cancelled. Nothing is ever written
// to a log: the only outputs are the protocol answers.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), maxMessageBytes)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if resp := s.handle(ctx, line); resp != nil {
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return enc.Encode(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeInvalidRequest, "message too large"}})
		}
		return err
	}
	return nil
}

func (s *Server) handle(ctx context.Context, line []byte) *response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return &response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeParse, "parse error"}}
	}
	notification := len(req.ID) == 0
	if !notification && !integerID.Match(req.ID) {
		// Whatever else the peer put in "id" is its own text; none of it is
		// copied back.
		return &response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{codeInvalidRequest, "invalid request"}}
	}
	fail := func(code int, msg string) *response {
		if notification {
			return nil
		}
		return &response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{code, msg}}
	}
	ok := func(result any) *response {
		if notification {
			return nil
		}
		return &response{JSONRPC: "2.0", ID: req.ID, Result: result}
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return fail(codeInvalidRequest, "invalid request")
	}
	switch req.Method {
	case "initialize":
		return ok(map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "keep", "version": serverVersion},
		})
	case "ping":
		return ok(map[string]any{})
	case "tools/list":
		return ok(map[string]any{"tools": s.tools.list()})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if notification {
			return nil // a call nobody can read the answer of is not run
		}
		if json.Unmarshal(req.Params, &p) != nil || p.Name == "" {
			return fail(codeInvalidParams, "invalid params")
		}
		res, known := s.tools.call(ctx, p.Name, p.Arguments)
		if !known {
			return fail(codeInvalidParams, "unknown tool")
		}
		return ok(res)
	default:
		if notification {
			return nil
		}
		return fail(codeMethodNotFound, "method not found")
	}
}
