package runnerproto

import (
	"encoding/json"
	"testing"
)

func TestDecodeValueRequestIsClosed(t *testing.T) {
	j := deployJob(t)
	good, _ := json.Marshal(ValueRequest{JobID: j.JobID})
	if req, err := DecodeValueRequest(good); err != nil || req.JobID != j.JobID {
		t.Fatal("valid value request rejected")
	}
	for _, bad := range []string{
		`{"job_id":"` + j.JobID + `","store_id":"other"}`,
		`{"job_id":"` + j.JobID + `","recipient":"other"}`,
		`{"job_id":"` + j.JobID + `","job_id":"` + j.JobID + `"}`,
		`{"JOB_ID":"` + j.JobID + `"}`,
		`{"job_id":"` + j.JobID + `"} {}`,
		`{"job_id":"` + j.JobID + `"}]`,
		`{"job_id":"` + j.JobID + `"`,
		`{}`, `null`, `[]`, `{"job_id":null}`, `{"job_id":"invalid"}`,
	} {
		if _, err := DecodeValueRequest([]byte(bad)); err == nil {
			t.Fatal("request outside closed schema accepted")
		}
	}
}
