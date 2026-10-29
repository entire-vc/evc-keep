package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// issueProblem inspects a token-issue response and returns "" when it carries
// both token and token_id, else a failure message. The response body holds
// the live token, so the message names only the status and the body length —
// never the body, never a slice of it.
func issueProblem(rec *httptest.ResponseRecorder, token, tokenID string) string {
	if rec.Code != http.StatusCreated {
		return fmt.Sprintf("issue token: status = %d, body length = %d", rec.Code, rec.Body.Len())
	}
	if token == "" || tokenID == "" {
		return fmt.Sprintf("issue response missing token/token_id: status = %d, body length = %d", rec.Code, rec.Body.Len())
	}
	return ""
}

// The failure text for an issue response with an empty token_id must not
// carry the token that sits in the same body.
func TestIssueProblem_EmptyTokenIDDoesNotEchoBody(t *testing.T) {
	c := canary.New()
	token := "keep_a_" + c.Value(1)
	body := fmt.Sprintf(`{"token":%q,"token_id":""}`, token)

	for _, status := range []int{http.StatusCreated, http.StatusOK} {
		rec := httptest.NewRecorder()
		rec.WriteHeader(status)
		_, _ = rec.WriteString(body)

		msg := issueProblem(rec, token, "")
		if msg == "" {
			t.Fatalf("status %d: empty token_id was not reported — detector is blind", status)
		}
		if c.In(msg) || canary.Of(token).In(msg) {
			t.Fatalf("status %d: failure message echoes the issue response body (message suppressed)", status)
		}
		// A slice of the token leaks it as surely as the whole: no 8-char window may appear.
		for i := 0; i+8 <= len(token); i++ {
			if strings.Contains(msg, token[i:i+8]) {
				t.Fatalf("status %d: failure message carries a slice of the token (message suppressed)", status)
			}
		}
		// Positive control: the detector sees the token when it is there.
		if !c.In(rec.Body.String()) {
			t.Fatal("positive control failed: canary not found in the body it was planted in")
		}
	}
}
