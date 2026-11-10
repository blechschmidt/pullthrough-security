package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// countingDoer is an upstream.Doer that counts the requests it is asked to make
// and fails them all.
type countingDoer struct{ calls atomic.Int32 }

func (d *countingDoer) Do(context.Context, upstream.Request) (*upstream.Response, error) {
	d.calls.Add(1)
	return nil, errors.New("no network in this test")
}

// The Homebrew backend normally recovers the formula version of a bottle it has
// not seen a manifest for from the formula JSON API, during Resolve. A sealed
// (air-gapped) instance wraps only Fetch (backends.Seal), so the backend itself
// must be built never to reach upstream from Resolve: buildBackend passes the
// sealed flag through.
func TestHomebrewBackendResolveIsOfflineWhenSealed(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, sealed := range []bool{false, true} {
		cfg := &config.Config{}
		cfg.Cache.Sealed = sealed
		doer := &countingDoer{}
		b, err := buildBackend(cfg, "homebrew",
			config.UpstreamConfig{Type: "homebrew", URL: "https://formulae.brew.sh"}, doer, upstream.Credentials{})
		if err != nil {
			t.Fatalf("sealed=%v: buildBackend: %v", sealed, err)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{
			Method: http.MethodGet,
			Path:   "/v2/homebrew/core/hello/blobs/sha256:" + digest,
		})
		if err != nil {
			t.Fatalf("sealed=%v: Resolve: %v", sealed, err)
		}
		// Either way the bottle is gated under a complete coordinate.
		if want := (backends.Coordinate{Name: "hello", Version: "sha256:" + digest}); res.Coordinate != want {
			t.Errorf("sealed=%v: coordinate = %+v, want %+v", sealed, res.Coordinate, want)
		}
		calls := doer.calls.Load()
		if sealed && calls != 0 {
			t.Errorf("sealed backend made %d upstream request(s) from Resolve", calls)
		}
		if !sealed && calls == 0 {
			t.Errorf("unsealed backend did not consult the formula API (the test would not detect a regression)")
		}
	}
}
