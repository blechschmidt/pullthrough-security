package backends

import (
	"errors"
	"fmt"
)

// StatusError reports that an upstream returned a non-success, non-304 HTTP
// status (e.g. 404 Not Found, 403 Forbidden). Backends return it from Fetch so
// the proxy core can map the failure onto an equivalent client-facing status
// instead of masking every upstream condition as a generic 502.
type StatusError struct {
	// Status is the upstream HTTP status code.
	Status int
	// URL is the upstream URL that produced the status, for diagnostics.
	URL string
	// Body is a short, truncated snippet of the upstream error body, when
	// available, to aid debugging without retaining large payloads.
	Body string
}

func (e *StatusError) Error() string {
	if e.URL != "" {
		return fmt.Sprintf("backends: upstream %s returned status %d", e.URL, e.Status)
	}
	return fmt.Sprintf("backends: upstream returned status %d", e.Status)
}

// AsStatusError extracts a *StatusError from err if present.
func AsStatusError(err error) (*StatusError, bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}
