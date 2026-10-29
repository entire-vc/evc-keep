package enrolltoken

import "errors"

// HostAttrs are administrator assertions bound to an enrollment token.
// They are not measured or attested by the runner. A nil UIDShared means
// legacy/unknown and cannot be treated as a dedicated-UID host.
type HostAttrs struct {
	UIDShared *bool             `json:"uid_shared"`
	Labels    map[string]string `json:"labels"`
}

var ErrInvalidHostAttrs = errors.New("enrolltoken: invalid host attributes")

// Validate accepts only the intentionally closed label vocabulary.
func (a HostAttrs) Validate() error {
	if a.UIDShared == nil {
		return ErrInvalidHostAttrs
	}
	for key, value := range a.Labels {
		switch key {
		case "environment":
			if value != "development" && value != "staging" && value != "production" {
				return ErrInvalidHostAttrs
			}
		case "platform":
			if value != "linux" && value != "darwin" {
				return ErrInvalidHostAttrs
			}
		default:
			return ErrInvalidHostAttrs
		}
	}
	return nil
}
