package backends

import (
	"context"
	"errors"
)

// ErrSealed indicates the proxy is running in sealed (offline/air-gapped) mode
// and an upstream fetch was refused. It lets the gateway distinguish a
// deliberately blocked fetch from a genuine upstream failure.
var ErrSealed = errors.New("backends: sealed (offline) mode; upstream fetch refused")

// sealedBackend wraps a Backend so that Fetch never reaches upstream. Resolve is
// pure (it maps a request to a cache key and URL without any network I/O) and is
// forwarded unchanged, so cache lookups and policy still work; only the actual
// retrieval is blocked. This seals the gateway's live (non-cacheable) serving
// path, complementing the cache-layer seal that covers cacheable artifacts.
type sealedBackend struct {
	Backend
}

// Fetch refuses to retrieve from upstream in sealed mode.
func (s sealedBackend) Fetch(_ context.Context, _ *Resolved) (*FetchResult, error) {
	return nil, ErrSealed
}

// Unwrap returns the underlying Backend that b wraps, peeling off the sealed
// wrapper when present. It lets callers (e.g. the metrics bridge) recover the
// concrete backend type for type assertions regardless of whether sealed mode is
// active. A backend that is not wrapped is returned as-is.
func Unwrap(b Backend) Backend {
	if s, ok := b.(sealedBackend); ok {
		return s.Backend
	}
	return b
}

// Seal returns a sealed wrapper around b that refuses upstream fetches. Backends
// that own their transport via the HTTPHandler capability (e.g. the Git
// smart-HTTP proxy, which serves from a local mirror) are returned unwrapped:
// their upstream access is governed by their own mirror/refresh policy, not the
// Resolve/Fetch path, and wrapping them would also hide their HTTPHandler
// capability.
func Seal(b Backend) Backend {
	if _, ok := b.(HTTPHandler); ok {
		return b
	}
	return sealedBackend{Backend: b}
}
