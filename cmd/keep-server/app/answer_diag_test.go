package app

import (
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// answerDiag prints a known error class and nothing else from the answer: a
// class-like value the server did not define, lowercase letters and
// underscores only, stays out of the failure message.
func TestAnswerDiagPrintsOnlyKnownClasses(t *testing.T) {
	answer := func(class string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		_ = json.NewEncoder(rec).Encode(map[string]string{"error_class": class, "message": "m"})
		return rec
	}
	// Positive control: a class apperr defines is named.
	if got := answerDiag(answer(string(apperr.ClassRateLimited))); !strings.Contains(got, string(apperr.ClassRateLimited)) {
		t.Fatal("a known error class is not printed; the check below proves nothing")
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'a' + raw[i]%26
	}
	val := string(raw)
	c := canary.Of(val)
	if !c.In("x" + val + "x") {
		t.Fatal("canary detector is blind")
	}
	for _, class := range []string{val, val + "_" + string(apperr.ClassNotFound), canary.New().Value(1)} {
		got := answerDiag(answer(class))
		if c.In(got) || strings.Contains(got, class) {
			t.Fatalf("an unknown error class reached the diagnostic (value of %d bytes); output suppressed", len(class))
		}
	}
}
