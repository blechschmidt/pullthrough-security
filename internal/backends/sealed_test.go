package backends

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type fetchBackend struct{ fetched bool }

func (b *fetchBackend) Name() string { return "pkg" }
func (b *fetchBackend) Resolve(context.Context, *Request) (*Resolved, error) {
	return &Resolved{CacheKey: "pkg:x", UpstreamURL: "https://up/x", Cacheable: true}, nil
}
func (b *fetchBackend) Fetch(context.Context, *Resolved) (*FetchResult, error) {
	b.fetched = true
	return &FetchResult{}, nil
}

func TestSealRefusesFetch(t *testing.T) {
	inner := &fetchBackend{}
	sealed := Seal(inner)

	// Resolve still works (it is pure and used for cache lookup/policy).
	if _, err := sealed.Resolve(context.Background(), &Request{Path: "/x"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	_, err := sealed.Fetch(context.Background(), &Resolved{})
	if !errors.Is(err, ErrSealed) {
		t.Errorf("Fetch err = %v, want ErrSealed", err)
	}
	if inner.fetched {
		t.Error("sealed backend reached the inner Fetch")
	}
}

// httpHandlerBackend additionally implements HTTPHandler (like the Git backend).
type httpHandlerBackend struct{ fetchBackend }

func (b *httpHandlerBackend) ServeBackendHTTP(http.ResponseWriter, *http.Request, string) {}

func TestSealPreservesHTTPHandlerBackends(t *testing.T) {
	inner := &httpHandlerBackend{}
	sealed := Seal(inner)

	// HTTPHandler backends own their transport (mirror); Seal must leave them
	// unwrapped so the capability is preserved.
	if _, ok := sealed.(HTTPHandler); !ok {
		t.Fatal("Seal hid the HTTPHandler capability")
	}
	if sealed != Backend(inner) {
		t.Error("Seal should return HTTPHandler backends unchanged")
	}
}
