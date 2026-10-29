package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// bot is the Telegram Bot API as an external boundary: a mock that records
// every request it receives.
type bot struct {
	mu   sync.Mutex
	reqs []recorded
	code int
}

type recorded struct {
	path string
	body string
	hdr  http.Header
}

func (b *bot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	b.reqs = append(b.reqs, recorded{path: r.URL.Path, body: string(raw), hdr: r.Header.Clone()})
	code := b.code
	b.mu.Unlock()
	if code != 0 {
		w.WriteHeader(code)
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func notice() ApprovalNotice {
	return ApprovalNotice{ApprovalID: uuid.MustParse("0192f0aa-1111-7222-8333-444455556666"), SecretName: "prod-db", SecretClass: "token", RequesterKind: "agent", TargetKind: "env-file"}
}

func newTG(t *testing.T, b *bot, token string) *Telegram {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	return NewTelegram(Config{Token: token, ChatID: "-1001", PublicURL: "https://keep.example.test", APIBase: srv.URL, Timeout: 2 * time.Second})
}

func TestNotificationCarriesOnlyTheClosedFields(t *testing.T) {
	c := canary.New()
	b := &bot{}
	tg := newTG(t, b, "123456:"+c.Value(9))
	if err := tg.ApprovalRequested(context.Background(), notice()); err != nil {
		t.Fatal(err)
	}
	if len(b.reqs) != 1 { // positive control: the mock really received a message
		t.Fatalf("mock received %d requests, want 1", len(b.reqs))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(b.reqs[0].body), &m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		if k != "chat_id" && k != "text" && k != "disable_web_page_preview" {
			t.Errorf("unexpected field %q in sendMessage body", k)
		}
	}
	text, _ := m["text"].(string)
	for _, want := range []string{"prod-db", "token", "agent", "env-file", "https://keep.example.test/console/approvals/0192f0aa-1111-7222-8333-444455556666"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q: %q", want, text)
		}
	}
	// The text is exactly the closed template: nothing else may ride along.
	if want := render(notice(), "https://keep.example.test"); text != want {
		t.Errorf("text %q differs from the template %q", text, want)
	}
	if c.In(b.reqs[0].body) || c.In(b.reqs[0].path+" "+b.reqs[0].hdr.Get("Authorization")) && strings.Contains(b.reqs[0].body, c.Value(9)) {
		t.Errorf("canary found in the message body")
	}
}

func TestNoticeFieldsAreAClosedList(t *testing.T) {
	var names []string
	rt := reflect.TypeOf(ApprovalNotice{})
	for i := 0; i < rt.NumField(); i++ {
		names = append(names, rt.Field(i).Name)
	}
	want := []string{"ApprovalID", "SecretName", "SecretClass", "RequesterKind", "TargetKind"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("ApprovalNotice fields %v, want exactly %v (extend the list only with the threat model)", names, want)
	}
}

func TestHostileNameCannotBreakTheMessage(t *testing.T) {
	b := &bot{}
	tg := newTG(t, b, "123456:abc")
	n := notice()
	n.SecretName = "x\n\nhttps://evil.example/login\u202e" + strings.Repeat("a", 500)
	if err := tg.ApprovalRequested(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(b.reqs[0].body), &m)
	text := m["text"].(string)
	if strings.Contains(text, "evil.example/login\n") || strings.Contains(text, "\u202e") || len(text) > 700 {
		t.Errorf("hostile name passed through: %q", text)
	}
	if strings.Count(text, "://") != 1 {
		t.Errorf("exactly one link allowed, got: %q", text)
	}
}

func TestFailureNeverReturnsTheTokenOrURL(t *testing.T) {
	c := canary.New()
	token := "123456:" + c.Value(9)
	for name, mk := range map[string]func() *Telegram{
		"http 500": func() *Telegram { return newTG(t, &bot{code: 500}, token) },
		"refused": func() *Telegram {
			return NewTelegram(Config{Token: token, ChatID: "1", PublicURL: "https://k.test", APIBase: "http://127.0.0.1:1", Timeout: time.Second})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := mk().ApprovalRequested(context.Background(), notice())
			if err == nil {
				t.Fatal("want an error")
			}
			s := err.Error() + " " + strings.Join(strings.Fields(err.Error()), " ")
			if c.In(s) || strings.Contains(s, "http://") || strings.Contains(s, "/bot") {
				t.Errorf("error leaks the token or URL: %q", s)
			}
		})
	}
}

func TestDisabledWithoutTokenSendsNothing(t *testing.T) {
	b := &bot{}
	srv := httptest.NewServer(b)
	defer srv.Close()
	for _, cfg := range []Config{{ChatID: "1", APIBase: srv.URL}, {Token: "1:a", APIBase: srv.URL}} {
		tg := NewTelegram(cfg)
		if tg != nil {
			t.Fatalf("channel must be off for %+v", cfg)
		}
		if err := tg.ApprovalRequested(context.Background(), notice()); err != nil { // nil receiver is a no-op
			t.Fatal(err)
		}
	}
	if len(b.reqs) != 0 {
		t.Fatal("a disabled channel sent a request")
	}
}

func TestSlowTelegramIsCutOffByTheTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	defer srv.Close()
	tg := NewTelegram(Config{Token: "1:a", ChatID: "1", PublicURL: "https://k.test", APIBase: srv.URL, Timeout: 100 * time.Millisecond})
	start := time.Now()
	if err := tg.ApprovalRequested(context.Background(), notice()); err == nil || time.Since(start) > time.Second {
		t.Fatalf("not cut off: err=%v after %v", err, time.Since(start))
	}
}
