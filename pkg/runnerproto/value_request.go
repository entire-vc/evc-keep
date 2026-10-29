package runnerproto

import (
	"encoding/json"
	"errors"
)

// ErrInvalidValueRequest never includes request text.
var ErrInvalidValueRequest = errors.New("runnerproto: invalid value request")

// DecodeValueRequest accepts only one exactly spelled job_id field. The
// authenticated peer and registered recipient key are never request fields.
func DecodeValueRequest(b []byte) (ValueRequest, error) {
	if !exactKeys(b, map[string]bool{"job_id": true}) {
		return ValueRequest{}, ErrInvalidValueRequest
	}
	var req ValueRequest
	if json.Unmarshal(b, &req) != nil || !uuidV7Re.MatchString(req.JobID) {
		return ValueRequest{}, ErrInvalidValueRequest
	}
	return req, nil
}
