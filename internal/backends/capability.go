package backends

import (
	"context"
	"net/http"
)

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

// Download describes a raw request that transfers content to the client, for
// the download log: what was fetched, in the terms the log uses for every other
// ecosystem.
type Download struct {
	// Name is what was downloaded — for Git, the repository ("octocat/Hello-World").
	Name string
	// Version is the version, when the request names one. A Git fetch names
	// none: the client negotiates what it wants inside the request body.
	Version string
	// Artifact is the file name of what was transferred, when there is one (a
	// Git LFS object's ID).
	Artifact string
	// Digest is the content digest the request addresses, when it does
	// ("sha256:…" for a Git LFS object).
	Digest string
}

// DownloadDescriber is an optional capability of an HTTPHandler backend. The
// proxy core learns what a request is about from Resolve; a backend that owns
// the raw request never goes through Resolve, so the core asks it instead.
//
// DescribeDownload is called before ServeBackendHTTP, with the same request and
// path. It reports ok=true when the request, if served, transfers content the
// client asked to obtain — a Git fetch, a Git LFS object — and ok=false for
// everything else the protocol exchanges on the way (capability and ref
// advertisements, batch negotiations). It must not consume the request body in
// a way ServeBackendHTTP can observe.
type DownloadDescriber interface {
	DescribeDownload(r *http.Request, repoPath string) (Download, bool)
}

// LoginProber is an optional capability of a backend whose clients check their
// credentials with a request of their own before they use them: SwiftPM's
// `swift package-registry login` POSTs to the registry's login endpoint
// (SE-0378) and stores the credentials only when that answers 200.
//
// The proxy core answers such a request itself and never forwards it. It
// reaches the backend only after access control has admitted the caller, so
// the credentials the client presented are good for the proxy — which is all
// the client asks. Forwarded, the request would be answered for the proxy's
// own upstream credentials, or — where a login endpoint issues a session —
// hand the caller a session of the proxy's account.
//
// LoginProbe reports whether a request (its method, and its path below the
// "/v1/<backend>" mount, as Resolve would receive it) is the client's
// credential check, and the response headers to answer it with.
type LoginProber interface {
	LoginProbe(method, repoPath string) (http.Header, bool)
}

type refusalRecorderKey struct{}

// WithRefusalRecorder returns a context through which a backend can report that
// an admission gate of its own refused the request. The proxy core attaches one
// to the requests it hands to an HTTPHandler backend; record is called with the
// gate's name.
func WithRefusalRecorder(ctx context.Context, record func(gate string)) context.Context {
	return context.WithValue(ctx, refusalRecorderKey{}, record)
}

// RecordRefusal reports that the named admission gate refused the request ctx
// belongs to. A backend that serves raw HTTP and runs a gate of its own — the
// Git backend's content gate on LFS objects — calls it where it refuses, so the
// download log can tell "refused by a gate" from "failed". It does nothing for
// a context that carries no recorder.
func RecordRefusal(ctx context.Context, gate string) {
	if record, _ := ctx.Value(refusalRecorderKey{}).(func(string)); record != nil {
		record(gate)
	}
}
