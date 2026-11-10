// Package backends defines the pluggable upstream abstraction. Each supported
// protocol (Git, pip, npm, cargo, Go modules, NuGet, Docker/OCI registry)
// implements the Backend interface so the proxy core can treat them uniformly.
//
// The interface is intentionally split into a Resolve phase (map an incoming
// request to a concrete upstream resource and cache key) and a Fetch phase
// (retrieve the bytes). This separation lets the proxy consult the cache and
// apply policy between resolution and retrieval.
package backends

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

// Request is a protocol-agnostic description of an inbound proxy request,
// derived from the underlying HTTP request (or SSH/Git invocation).
type Request struct {
	Method string
	// Path is the request path with the backend route prefix already stripped,
	// e.g. for "/npm/lodash/-/lodash-4.17.21.tgz" the backend sees
	// "/lodash/-/lodash-4.17.21.tgz".
	Path   string
	Query  url.Values
	Header http.Header
	// Body is the request body for write/upload methods; nil for reads.
	Body io.Reader
}

// Coordinate is the logical identity of a resource within a backend's
// ecosystem.
type Coordinate struct {
	Name    string
	Version string
}

// Resolved is the outcome of Backend.Resolve: enough information to fetch the
// resource and to address it in the cache.
type Resolved struct {
	Coordinate Coordinate
	// UpstreamURL is the absolute URL (or transport-specific locator) from which
	// the resource should be fetched on a cache miss.
	UpstreamURL string
	// CacheKey is the key under which the resource is (or will be) cached.
	// Backends should prefer content digests when available; otherwise a stable
	// logical key derived from the coordinate.
	CacheKey string
	// Digest is the expected content digest (e.g. "sha256:..."), when the
	// backend can determine it during resolution. Empty when unknown.
	Digest string
	// MediaType is the content type of the resource, when known.
	MediaType string
	// Cacheable reports whether the resolved resource may be cached. Mutable
	// listings (e.g. package index documents) are typically not cacheable, or
	// are cached only briefly.
	Cacheable bool
	// IfNoneMatch, when non-empty, asks Fetch to perform a conditional upstream
	// request by sending an If-None-Match header with this validator. The proxy
	// sets it to a previously cached ETag when revalidating a non-cacheable (or
	// stale) resource. A 304 response is reported via FetchResult.NotModified.
	IfNoneMatch string
	// Metadata carries backend-specific attributes to persist with the cache
	// entry.
	Metadata map[string]string
}

// FetchResult is the outcome of Backend.Fetch. The caller owns Content and must
// Close it.
type FetchResult struct {
	Resolved  *Resolved
	Content   io.ReadCloser
	Size      int64
	Digest    string
	MediaType string
	// Header holds upstream response headers worth propagating to the client.
	Header http.Header
	// Status is the upstream status code (HTTP), or 0 for non-HTTP backends.
	Status int
	// NotModified reports that a conditional fetch (Resolved.IfNoneMatch) was
	// answered 304 Not Modified by the upstream. When true, Content is nil and
	// the caller should serve the previously cached representation.
	NotModified bool
}

// Backend is an upstream protocol adapter. Implementations must be safe for
// concurrent use and must honor context cancellation.
type Backend interface {
	// Name returns the backend's route identifier, e.g. "npm", "pip", "go",
	// "cargo", "nuget", "docker", "git".
	Name() string

	// Resolve maps an inbound request to a concrete upstream resource. It does
	// not transfer content. Returning ErrNotSupported indicates the request is
	// not handled by this backend.
	Resolve(ctx context.Context, req *Request) (*Resolved, error)

	// Fetch retrieves the resource described by a prior Resolve result.
	Fetch(ctx context.Context, resolved *Resolved) (*FetchResult, error)
}
