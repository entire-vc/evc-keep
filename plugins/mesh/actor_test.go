package mesh_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/plugins/mesh"
	"github.com/google/uuid"
)

// meStub answers GET /api/v1/ext/me for one bearer token with the actor id it
// is given; the body also echoes the canary, as a careless Mesh could.
type meStub struct {
	mu     sync.Mutex
	token  string
	actor  string
	echo   string
	status int // when non-zero, /me answers this status with echo as body
	calls  int
	srv    *httptest.Server
}

func newMeStub(t *testing.T, token, actor, echo string) *meStub {
	s := &meStub{token: token, actor: actor, echo: echo}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/ext/me" || r.Header.Get("Authorization") != "Bearer "+s.token {
			http.Error(w, "unauthorized "+s.echo, http.StatusUnauthorized)
			return
		}
		if s.status != 0 {
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(s.echo))
			return
		}
		_, _ = fmt.Fprintf(w, `{"actor":"ext:x","actor_id":%q,"note":%q}`, s.actor, s.echo)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func actorCheck(s *meStub, account string, tok mesh.TokenSource, logs *bytes.Buffer) mesh.ActorCheck {
	return mesh.ActorCheck{
		BaseURL:   s.srv.URL,
		AccountID: account,
		Gate:      tok,
		Log:       slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

func fixedToken(v string) mesh.TokenSource {
	return func(context.Context) (mesh.Token, error) { return mesh.Token(v), nil }
}

// errSurfaces is every text of err a caller could print.
func errSurfaces(err error) string {
	if err == nil {
		return ""
	}
	out := []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)}
	for e := errors.Unwrap(err); e != nil; e = errors.Unwrap(e) {
		out = append(out, e.Error())
	}
	return strings.Join(out, "\n")
}

// The gate's token is the canary. When the self-rotation account is the gate's
// own actor the start is refused with the class text, and neither that error
// nor the log carries the token or the answer of /me.
func TestActorCheckSameActorRefusedWithoutLeak(t *testing.T) {
	c := canary.New()
	tok := "ext_" + c.Value(0)
	if !c.In("x "+tok) || !c.In(hex.EncodeToString([]byte(tok))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	account := uuid.NewString()
	s := newMeStub(t, tok, account, c.Value(1))
	var logs bytes.Buffer
	err := mesh.CheckSelfRotateActor(context.Background(), actorCheck(s, account, fixedToken(tok), &logs))
	if !errors.Is(err, mesh.ErrSameActor) {
		t.Fatalf("same actor accepted: %v", err)
	}
	if err.Error() != "self-rotation account is the gate's actor" {
		t.Fatalf("error text %q", err)
	}
	if s.calls != 1 {
		t.Fatalf("/me called %d times, want 1", s.calls)
	}
	if logs.Len() == 0 {
		t.Fatal("no log line: the logger is not connected")
	}
	if !strings.Contains(logs.String(), `"error_class":"same_actor"`) {
		t.Fatalf("no class in the log: %s", logs.String())
	}
	if c.In(errSurfaces(err)) || c.In(logs.String()) {
		t.Fatalf("canary leaked: err=%q log=%s", errSurfaces(err), logs.String())
	}
	if s.srv.URL != "" && strings.Contains(errSurfaces(err), s.srv.URL) {
		t.Fatalf("error names the URL: %q", err)
	}
}

// The comparison is of UUIDs, not of strings: Mesh may answer in upper case.
func TestActorCheckSameActorAnyCase(t *testing.T) {
	account := uuid.NewString()
	s := newMeStub(t, stubToken, strings.ToUpper(account), "")
	var logs bytes.Buffer
	if err := mesh.CheckSelfRotateActor(context.Background(), actorCheck(s, account, fixedToken(stubToken), &logs)); !errors.Is(err, mesh.ErrSameActor) {
		t.Fatalf("same actor in upper case accepted: %v", err)
	}
}

// Different actors: the start goes on.
func TestActorCheckDifferentActorsPass(t *testing.T) {
	c := canary.New()
	tok := "ext_" + c.Value(0)
	s := newMeStub(t, tok, uuid.NewString(), c.Value(1))
	var logs bytes.Buffer
	if err := mesh.CheckSelfRotateActor(context.Background(), actorCheck(s, uuid.NewString(), fixedToken(tok), &logs)); err != nil {
		t.Fatalf("different actors refused: %v", err)
	}
	if s.calls != 1 {
		t.Fatalf("/me called %d times, want 1", s.calls)
	}
	if logs.Len() == 0 || c.In(logs.String()) {
		t.Fatalf("log empty or leaked: %s", logs.String())
	}
}

// /me unreachable, refusing, answering garbage or without an actor id, or no
// gate token at all: the start is not failed (the gate answers 503 anyway), a
// warning by class is logged, and nothing of the token or the body leaks.
func TestActorCheckUnavailableWarnsWithoutLeak(t *testing.T) {
	c := canary.New()
	tok := "ext_" + c.Value(0)
	account := uuid.NewString()
	cases := []struct {
		name  string
		setup func(s *meStub) mesh.TokenSource
	}{
		{"server_error", func(s *meStub) mesh.TokenSource { s.status = http.StatusServiceUnavailable; return fixedToken(tok) }},
		{"denied", func(s *meStub) mesh.TokenSource { return fixedToken("ext_other") }},
		{"no_actor_id", func(s *meStub) mesh.TokenSource { s.actor = ""; return fixedToken(tok) }},
		{"bad_actor_id", func(s *meStub) mesh.TokenSource { s.actor = c.Value(2); return fixedToken(tok) }},
		{"not_json", func(s *meStub) mesh.TokenSource { s.status = http.StatusOK; return fixedToken(tok) }},
		{"no_token", func(s *meStub) mesh.TokenSource {
			return func(context.Context) (mesh.Token, error) { return "", errors.New("file " + tok) }
		}},
		{"down", func(s *meStub) mesh.TokenSource { s.srv.Close(); return fixedToken(tok) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeStub(t, tok, account, c.Value(1))
			src := tc.setup(s)
			var logs bytes.Buffer
			err := mesh.CheckSelfRotateActor(context.Background(), actorCheck(s, account, src, &logs))
			if err != nil {
				t.Fatalf("unavailable /me failed the start: %v", err)
			}
			if !strings.Contains(logs.String(), `"level":"WARN"`) || !strings.Contains(logs.String(), `"error_class"`) {
				t.Fatalf("no warning by class: %s", logs.String())
			}
			if c.In(logs.String()) {
				t.Fatalf("canary leaked: %s", logs.String())
			}
		})
	}
}

// A configuration the check cannot run with is refused, not skipped.
func TestActorCheckBadConfig(t *testing.T) {
	s := newMeStub(t, stubToken, uuid.NewString(), "")
	var logs bytes.Buffer
	for _, cfg := range []mesh.ActorCheck{
		actorCheck(s, "not-a-uuid", fixedToken(stubToken), &logs),
		actorCheck(s, uuid.NewString(), nil, &logs),
		{BaseURL: "http://mesh.example", AccountID: uuid.NewString(), Gate: fixedToken(stubToken)},
	} {
		if err := mesh.CheckSelfRotateActor(context.Background(), cfg); !errors.Is(err, mesh.ErrConfig) {
			t.Fatalf("bad config %+v: %v", cfg.BaseURL, err)
		}
	}
}
