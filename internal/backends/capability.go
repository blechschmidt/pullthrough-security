package backends

import "net/http"

// HTTPHandler is an optional capability a Backend may implement when its
// protocol cannot be expressed through the Resolve/Fetch flow — for example Git
// smart HTTP, which negotiates over POST with a streaming request body and a
// dynamically generated response that depends on the client's wants/haves.
//
// When the proxy core finds that the backend addressed by a request implements
// HTTPHandler, it delegates the raw HTTP request to ServeBackendHTTP instead of
// invoking Resolve/Fetch, and does not impose the GET/HEAD-only restriction.
// repoPath is the request path with the "/v1/<backend>" route prefix already
// stripped (it retains its leading slash), exactly as Resolve would receive it
// in Request.Path.
type HTTPHandler interface {
	Backend
	ServeBackendHTTP(w http.ResponseWriter, r *http.Request, repoPath string)
}
