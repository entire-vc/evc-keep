package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// The wire types below mirror internal/api/types.go's Secret, StoreRef and
// SecretVersion field-for-field, deliberately duplicated rather than
// imported: cmd/keep is a thin HTTP client and must decode exactly what the
// documented REST contract (threat model §4.3) promises, not reach into the
// server's own internal package to get there. Divergence between the two is
// caught the same way any other client-server contract drifts, by the e2e
// tests round-tripping real server responses through these types.

type storeRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

type secret struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Scope       string    `json:"scope"`
	Class       string    `json:"class"`
	Type        string    `json:"type"`
	Description string    `json:"description,omitempty"`
	Store       storeRef  `json:"store"`
	ProviderRef string    `json:"provider_ref"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type secretVersion struct {
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	Fingerprint string    `json:"fingerprint"`
	Length      int       `json:"length"`
	Status      string    `json:"status"`
}

// errSecretNameNotFound builds the same secret_not_found shape
// [handleSecretMeta]'s server-side ID lookup returns for a genuine miss
// (internal/catalog.NotFoundByID) — the CLI resolves a name to an id via
// [cmdList]'s own scoped listing first (there is no by-name lookup route),
// and that listing already answers identically for "no such secret" and
// "exists, but outside this token's org or rights" (see handleListSecrets'
// own doc): a name absent from it is indistinguishable from either, so
// naming the class here does not open a new oracle, it just gives the
// client-side resolution step the same externally-visible failure the
// server itself would.
func errSecretNameNotFound() *apiError {
	return &apiError{Status: http.StatusNotFound, ErrorClass: "secret_not_found", Message: "secret not found"}
}

func listSecrets(c *client, scopeLevel, scopeID string) ([]secret, error) {
	q := url.Values{"scope_level": {scopeLevel}, "scope_id": {scopeID}}
	body, err := c.do(http.MethodGet, "/secrets", q, nil)
	if err != nil {
		return nil, err
	}
	var secrets []secret
	if err := json.Unmarshal(body, &secrets); err != nil {
		return nil, fmt.Errorf("parse server response: %w", err)
	}
	return secrets, nil
}

// resolveSecretByName finds the secret named name at the given scope. The
// REST API has no by-name lookup (handleSecretMeta takes only a secret_id),
// so this lists the scope and filters client-side.
func resolveSecretByName(c *client, scopeLevel, scopeID, name string) (secret, error) {
	secrets, err := listSecrets(c, scopeLevel, scopeID)
	if err != nil {
		return secret{}, err
	}
	for _, s := range secrets {
		if s.Name == name {
			return s, nil
		}
	}
	return secret{}, errSecretNameNotFound()
}

func cmdList(c *client, scopeLevel, scopeID string, jsonOut bool, w io.Writer) error {
	secrets, err := listSecrets(c, scopeLevel, scopeID)
	if err != nil {
		return err
	}
	if jsonOut {
		return writeJSONValue(w, secrets)
	}
	return writeSecretTable(w, secrets)
}

func cmdMeta(c *client, scopeLevel, scopeID, name string, jsonOut bool, w io.Writer) error {
	s, err := resolveSecretByName(c, scopeLevel, scopeID, name)
	if err != nil {
		return err
	}
	body, err := c.do(http.MethodGet, "/secrets/"+s.ID, nil, nil)
	if err != nil {
		return err
	}
	var got secret
	if err := json.Unmarshal(body, &got); err != nil {
		return fmt.Errorf("parse server response: %w", err)
	}
	if jsonOut {
		return writeJSONValue(w, got)
	}
	return writeSecretDetail(w, got)
}

func cmdVersion(c *client, scopeLevel, scopeID, name string, jsonOut bool, w io.Writer) error {
	s, err := resolveSecretByName(c, scopeLevel, scopeID, name)
	if err != nil {
		return err
	}
	body, err := c.do(http.MethodGet, "/secrets/"+s.ID+"/versions", nil, nil)
	if err != nil {
		return err
	}
	var versions []secretVersion
	if err := json.Unmarshal(body, &versions); err != nil {
		return fmt.Errorf("parse server response: %w", err)
	}
	if jsonOut {
		return writeJSONValue(w, versions)
	}
	return writeVersionTable(w, versions)
}

type createRefInput struct {
	ScopeLevel  string
	ScopeID     string
	Name        string
	Class       string
	Type        string
	ProviderRef string
	Description string
}

func (in createRefInput) validate() error {
	switch {
	case in.ScopeLevel == "" || in.ScopeID == "":
		return errors.New("--scope-level and --scope-id are required")
	case in.Name == "":
		return errors.New("a secret name is required")
	case in.Class == "":
		return errors.New("--class is required")
	case in.Type == "":
		return errors.New("--type is required")
	case in.ProviderRef == "":
		return errors.New("--provider-ref is required")
	}
	return nil
}

func cmdCreateRef(c *client, in createRefInput, jsonOut bool, w io.Writer) error {
	if err := in.validate(); err != nil {
		return err
	}
	reqBody := map[string]string{
		"scope_level":  in.ScopeLevel,
		"scope_id":     in.ScopeID,
		"name":         in.Name,
		"class":        in.Class,
		"type":         in.Type,
		"provider_ref": in.ProviderRef,
	}
	if in.Description != "" {
		reqBody["description"] = in.Description
	}
	body, err := c.do(http.MethodPost, "/secrets", nil, reqBody)
	if err != nil {
		return err
	}
	var created secret
	if err := json.Unmarshal(body, &created); err != nil {
		return fmt.Errorf("parse server response: %w", err)
	}
	if jsonOut {
		return writeJSONValue(w, created)
	}
	return writeSecretDetail(w, created)
}

// auditVerifyResult mirrors internal/api.AuditVerifyResult (threat model
// §4.3, the audit verify result) field for field. The result carries no
// journal record content by construction; BrokenID is already a ULID or the
// fixed "(malformed id)" placeholder when it arrives.
type auditVerifyResult struct {
	OK             bool   `json:"ok"`
	RequestID      string `json:"request_id"`
	Checked        int64  `json:"checked"`
	BrokenID       string `json:"broken_id,omitempty"`
	BrokenPosition int64  `json:"broken_position,omitempty"`
	BreakKind      string `json:"break_kind,omitempty"`
}

// cmdAuditVerify prints the server's verdict, with its free-form strings held
// to the closed sets the server promises, and reports whether the chain
// verified clean.
func cmdAuditVerify(c *client, jsonOut bool, w io.Writer) (bool, error) {
	body, err := c.do(http.MethodGet, "/audit/verify", nil, nil)
	if err != nil {
		return false, err
	}
	var res auditVerifyResult
	if err := json.Unmarshal(body, &res); err != nil {
		return false, fmt.Errorf("parse server response: %w", err)
	}
	res.BrokenID, res.BreakKind = sanitizeBreak(res.BrokenID, res.BreakKind)
	if !auditRequestID.MatchString(res.RequestID) {
		res.RequestID = "(unexpected value)"
	}
	if jsonOut {
		err = writeJSONValue(w, res)
	} else {
		err = writeAuditVerifyDetail(w, res)
	}
	return res.OK, err
}

// sanitizeBreak keeps the two free-form strings of an audit verdict inside the
// closed sets the server promises (a record id, "(malformed id)", or one of four
// break kinds); a misbehaving server cannot push anything else, such as terminal
// control sequences, through the CLI's output.
func sanitizeBreak(id, kind string) (string, string) {
	if id != "" && id != "(malformed id)" && !auditULID.MatchString(id) {
		id = "(unexpected value)"
	}
	switch kind {
	case "", "hash", "link", "sequence", "head":
	default:
		kind = "(unexpected value)"
	}
	return id, kind
}

// auditRequestID is the request id shape internal/reqid accepts.
var auditRequestID = regexp.MustCompile(`^[A-Za-z0-9-]{1,36}$`)

var auditULID = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
