package mesh_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

const stubToken = "ext_svc-token-for-tests" //nolint:gosec // fake token of the in-process stub

// stubMesh is a stand-in for the Mesh agent-keys API. It never talks to a
// live Mesh and holds only fake keys.
type stubMesh struct {
	t         *testing.T
	mu        sync.Mutex
	keys      map[string]string // key_id -> status
	value     string            // value returned by POST
	fail      int               // when non-zero, every call answers this status
	failTxt   string            // body of the failure answer
	agent     string
	note      string          // extra field in list/POST answers
	badID     string          // when set, POST and list answer this key_id
	primaryOn bool            // the original key is still active
	emptyRev  string          // when set, the list carries this key with revoked_at ""
	values    []string        // when non-empty, each POST pops the next value
	delFail   int             // the next delFail DELETE calls answer 503
	delSeen   int             // DELETE calls received
	delIDs    []string        // path key id of every DELETE, in order
	delNoop   bool            // DELETE answers 204 but the key stays active
	postID    string          // when set, POST answers this existing key_id and creates none
	postBad   string          // when set, POST answers this key_id; list is unaffected
	del404    bool            // DELETE answers 404 for every key, listed or not
	newStat   string          // when set, keys created by POST get this status
	token     string          // accepted bearer token; stubToken when empty
	delFailID string          // when set, DELETE of this key id answers 500
	accept    map[string]bool // extra accepted Authorization headers (a rotated token)
	delAuth   []string        // Authorization header of every DELETE
	srv       *httptest.Server
}

func newStub(t *testing.T, agent, value string) *stubMesh {
	s := &stubMesh{t: t, keys: map[string]string{}, value: value, agent: agent}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubMesh) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := stubToken
	if s.token != "" {
		want = s.token
	}
	got := r.Header.Get("Authorization")
	if r.Method == http.MethodDelete {
		s.delAuth = append(s.delAuth, got)
	}
	// Mesh's agent_key:rotate belongs to an extension actor: Bearer ext_…. An
	// agent key (agk_…) is X-Agent-Key only and is never a Bearer.
	if !strings.HasPrefix(got, "Bearer ext_") || (got != "Bearer "+want && !s.accept[got]) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.fail != 0 {
		w.WriteHeader(s.fail)
		_, _ = w.Write([]byte(s.failTxt))
		return
	}
	base := "/api/v1/agents/" + s.agent + "/keys"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == base:
		id := uuid.NewString()
		if s.postID == "" {
			s.keys[id] = "active"
			if s.newStat != "" {
				s.keys[id] = s.newStat
			}
		}
		val := s.value
		if len(s.values) > 0 {
			val, s.values = s.values[0], s.values[1:]
		}
		out := id
		if s.badID != "" {
			out = s.badID
		}
		if s.postID != "" {
			out = s.postID
		}
		if s.postBad != "" {
			out = s.postBad
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"key_id": out, "api_key": val, "agent_id": "stub", "fingerprint": "mesh-fp", "status": "active", "note": s.note,
		})
	case r.Method == http.MethodGet && r.URL.Path == base:
		// Mesh always lists the agent's original key, as "primary" (here already revoked).
		list := []map[string]any{{"id": "primary", "primary": true, "revoked_at": "2026-01-01T00:00:00Z"}}
		if s.primaryOn {
			list[0]["revoked_at"] = nil
		}
		if s.badID != "" {
			list = append(list, map[string]any{"id": s.badID, "primary": false, "revoked_at": nil, "note": s.note})
		}
		if s.emptyRev != "" {
			list = append(list, map[string]any{"id": s.emptyRev, "primary": false, "revoked_at": ""})
		}
		for id, st := range s.keys {
			var revoked any // Mesh's list has no status: a revoked key carries revoked_at
			if st != "active" {
				revoked = "2026-01-01T00:00:00Z"
			}
			list = append(list, map[string]any{"id": id, "primary": false, "fingerprint": "mesh-fp", "revoked_at": revoked, "note": s.note})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": list})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"/"):
		id := strings.TrimPrefix(r.URL.Path, base+"/")
		s.delSeen++
		s.delIDs = append(s.delIDs, id)
		if s.delFail > 0 {
			s.delFail--
			http.Error(w, "backend down", http.StatusServiceUnavailable)
			return
		}
		if id == s.delFailID {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		// The original key, as Mesh does it: refused while it is the agent's
		// last active key, otherwise ended (again, if it already was).
		if id == "primary" && !s.del404 {
			if s.primaryOn && s.activeLocked() == 0 {
				http.Error(w, "cannot revoke the last active key of the agent", http.StatusConflict)
				return
			}
			if !s.delNoop {
				s.primaryOn = false
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if _, ok := s.keys[id]; !ok || s.del404 {
			http.Error(w, "no such key", http.StatusNotFound)
			return
		}
		if !s.delNoop {
			s.keys[id] = "revoked"
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// activeLocked counts the active keys other than the original one; s.mu held.
func (s *stubMesh) activeLocked() int {
	n := 0
	for _, st := range s.keys {
		if st == "active" {
			n++
		}
	}
	return n
}
