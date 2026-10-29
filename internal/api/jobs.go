package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/dispatch"
	"github.com/entire-vc/evc-keep/internal/mtls"
	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"io"
	"net/http"
	"time"
)

type RunnerJobs interface {
	Poll(context.Context, mtls.Principal) (runnerproto.SignedJob, bool, error)
	Material(context.Context, mtls.Principal, string) (runnerproto.ValueEnvelope, error)
	Result(context.Context, mtls.Principal, string, runnerproto.Result) error
}

func jobPeer(w http.ResponseWriter, r *http.Request, jobs RunnerJobs) (mtls.Principal, bool) {
	w.Header().Set("Cache-Control", "no-store")
	p, ok := mtls.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, apperr.ClassPermissionDenied, "runner authentication required", reqid.FromContext(r.Context()))
		return mtls.Principal{}, false
	}
	if jobs == nil {
		writeJobError(w, r, dispatch.ErrUnavailable)
		return mtls.Principal{}, false
	}
	return p, true
}

func handleNextJob(jobs RunnerJobs) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := jobPeer(w, r, jobs)
		if !ok {
			return
		}
		// Extend only this long-poll response beyond the server's normal write
		// deadline; other endpoints retain their short default timeout.
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			writeJobError(w, r, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		job, found, err := jobs.Poll(ctx, p)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			writeJobError(w, r, err)
			return
		}
		if !found {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)
	})
}

func handleJobMaterial(jobs RunnerJobs) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := jobPeer(w, r, jobs)
		if !ok {
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			invalidJobBody(w, r)
			return
		}
		req, err := runnerproto.DecodeValueRequest(body)
		if err != nil {
			invalidJobBody(w, r)
			return
		}
		envelope, err := jobs.Material(r.Context(), p, req.JobID)
		if err != nil {
			writeJobError(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(envelope)
	})
}

func handleJobResult(jobs RunnerJobs) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := jobPeer(w, r, jobs)
		if !ok {
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			invalidJobBody(w, r)
			return
		}
		result, err := runnerproto.DecodeResult(body)
		if err != nil {
			invalidJobBody(w, r)
			return
		}
		if err := jobs.Result(r.Context(), p, r.PathValue("job_id"), result); err != nil {
			writeJobError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func invalidJobBody(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusBadRequest, apperr.ClassInvalidArgument, "invalid runner job request", reqid.FromContext(r.Context()))
}
func writeJobError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, dispatch.ErrNotFound) {
		writeError(w, http.StatusNotFound, apperr.ClassNotFound, "job unavailable", reqid.FromContext(r.Context()))
		return
	}
	writeError(w, http.StatusServiceUnavailable, apperr.ClassNotReady, "runner job service unavailable", reqid.FromContext(r.Context()))
}
