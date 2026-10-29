package enrolltoken

import (
	"encoding/json"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"testing"
)

func TestIssueResultNeverLeaksThroughJSON(t *testing.T) {
	c := canary.New()
	r := IssueResult{Token: NewToken(c.Value(1))}
	positive, err := json.Marshal(r.Token.Reveal())
	if err != nil || !c.In(string(positive)) {
		t.Fatal("JSON canary positive control failed")
	}
	for name, value := range map[string]any{"value": r, "pointer": &r, "struct": struct{ Result IssueResult }{r}, "pointer-struct": struct{ Result *IssueResult }{&r}, "slice": []IssueResult{r}, "map": map[string]any{"result": &r}} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(value)
			if c.In(string(b)) || (err != nil && c.In(err.Error())) {
				t.Error("IssueResult exposed its token through JSON")
			}
			if err == nil {
				t.Error("IssueResult JSON did not refuse implicit serialization")
			}
		})
	}
}
