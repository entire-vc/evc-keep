// Package notify tells a human that an approval is waiting. It carries a
// closed set of fields and a link into the console; a decision is never made
// from here, and no value, path or reason ever enters a message.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// ApprovalNotice is the whole input of a notification. Adding a field means
// changing the threat model first; TestNoticeFieldsAreAClosedList pins it.
type ApprovalNotice struct {
	ApprovalID    uuid.UUID
	SecretName    string
	SecretClass   string
	RequesterKind string
	TargetKind    string
}

// ErrSend is the only error a sender returns. It never wraps the transport
// error: that one contains the request URL, and the URL contains the bot token.
var ErrSend = errors.New("notification not delivered")

const defaultAPI = "https://api.telegram.org"

// Config configures the Telegram channel. An empty Token or ChatID turns the
// channel off (NewTelegram returns nil).
type Config struct {
	Token     string
	ChatID    string
	PublicURL string
	// APIBase overrides the Bot API host; tests point it at a mock.
	APIBase string
	Timeout time.Duration
}

// Telegram sends approval notifications through the Bot API.
type Telegram struct {
	token, chatID, publicURL, api string
	client                        *http.Client
}

// NewTelegram returns nil when the channel is not configured; a nil *Telegram
// is a valid no-op sender.
func NewTelegram(c Config) *Telegram {
	if c.Token == "" || c.ChatID == "" {
		return nil
	}
	if c.APIBase == "" {
		c.APIBase = defaultAPI
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	return &Telegram{token: c.Token, chatID: c.ChatID, publicURL: strings.TrimRight(c.PublicURL, "/"), api: strings.TrimRight(c.APIBase, "/"),
		client: &http.Client{Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// clean keeps a user-chosen name printable and short: no line breaks, no
// bidi or control characters, no link-forming punctuation, at most 64 runes.
func clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == 64 {
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) && r != ' ' {
			continue
		}
		if r == '.' || r == '/' || r == ':' || r == '@' { // nothing the chat could turn into a link or mention
			r = '_'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// closed returns v when it is a short lowercase token, else "?".
func closed(v string) string {
	if v == "" || len(v) > 32 {
		return "?"
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return "?"
		}
	}
	return v
}

func render(n ApprovalNotice, publicURL string) string {
	return fmt.Sprintf("Keep: a request waits for approval\nSecret: %s (%s)\nRequested by: %s\nTarget: %s\n%s/console/approvals/%s",
		clean(n.SecretName), closed(n.SecretClass), closed(n.RequesterKind), closed(n.TargetKind), strings.TrimRight(publicURL, "/"), n.ApprovalID)
}

// ApprovalRequested sends one message. The returned error carries no detail.
func (t *Telegram) ApprovalRequested(ctx context.Context, n ApprovalNotice) error {
	if t == nil {
		return nil
	}
	body, err := json.Marshal(map[string]any{"chat_id": t.chatID, "text": render(n, t.publicURL), "disable_web_page_preview": true})
	if err != nil {
		return ErrSend
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.api+"/bot"+t.token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return ErrSend
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return ErrSend
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return ErrSend
	}
	return nil
}
