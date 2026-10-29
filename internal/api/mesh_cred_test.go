package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// A decoded install request must not print its credentials through any
// formatter, encoder or logger, so a stray log line cannot expose them.
func TestMeshInstallRequestNeverPrintsCredentials(t *testing.T) {
	c := canary.New()
	tok, sec := c.Value(1), c.Value(2)
	if !c.In("x"+tok) || !c.In(fmt.Sprintf("%x", tok)) {
		t.Fatal("canary detector is blind")
	}
	body := fmt.Sprintf(`{"mesh_url":"https://mesh.example","workspace_id":"w","extension_token":%q,"events_endpoint_secret":%q}`, tok, sec)
	var req meshInstallRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if string(req.ExtensionToken) != tok || string(req.EventsEndpointSecret) != sec {
		t.Fatal("decoding lost the credentials")
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("req", "req", req, "tok", req.ExtensionToken)
	enc, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	outs := []string{
		fmt.Sprintf("%v %+v %#v %s %q %x", req, req, req, req, req, req),
		fmt.Sprint(req.ExtensionToken, req.EventsEndpointSecret),
		fmt.Sprintf("%#v %+v", req.ExtensionToken, req.EventsEndpointSecret),
		logs.String(),
		string(enc),
	}
	if logs.Len() == 0 {
		t.Fatal("logger captured nothing")
	}
	for i, o := range outs {
		if c.In(o) {
			t.Fatalf("credential printed on output #%d (%d bytes); the output is not printed", i, len(o))
		}
	}
}
