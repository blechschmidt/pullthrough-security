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
	// Location, when set on a 3xx Status, is the client-facing redirect target
	// the proxy core relays in the response's Location header. A backend sets it
	// only after mapping the upstream's own Location onto its mount, so a relayed
	// redirect leads the client back through the proxy; it stays empty when the
	// target cannot be expressed there, and the status is then relayed without a
	// target rather than steering the client past the proxy.
	Location string
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
