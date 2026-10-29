package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (r *deadlineRecorder) SetWriteDeadline(d time.Time) error { r.deadline = d; return nil }

func TestStatusRecorderPreservesResponseDeadlines(t *testing.T) {
	r := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	w := &statusRecorder{ResponseWriter: r, status: http.StatusOK}
	want := time.Now().Add(time.Second)
	if err := http.NewResponseController(w).SetWriteDeadline(want); err != nil || !r.deadline.Equal(want) {
		t.Fatal("logging wrapper blocked response deadline control")
	}
}
