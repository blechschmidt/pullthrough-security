package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// fakeInterceptor records the arguments Run is called with and exercises the
// supplied serve handler, so the test can confirm the gateway wires the
// interceptor into its /v1 pipeline.
type fakeInterceptor struct {
	started    chan struct{}
	gotAddr    string
	dispatched *http.Response
}

func (f *fakeInterceptor) Run(ctx context.Context, listenAddr string, serve http.Handler) error {
	f.gotAddr = listenAddr
	// Simulate an intercepted, rewritten request flowing into the gateway.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/unknown-backend/foo", nil)
	serve.ServeHTTP(rr, req)
	f.dispatched = rr.Result()
	close(f.started)
	<-ctx.Done()
	return nil
}

func TestGatewayStartsInterceptor(t *testing.T) {
	fi := &fakeInterceptor{started: make(chan struct{})}
	g, err := New(Dependencies{
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:       cache.NewMemoryCache(),
		Backends:    backends.NewRegistry(),
		Interceptor: fi,
	}, Options{
		HTTPAddr:        "127.0.0.1:0",
		InterceptAddr:   ":31280",
		ShutdownTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()

	select {
	case <-fi.started:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("interceptor Run was not started")
	}

	if fi.gotAddr != ":31280" {
		t.Errorf("interceptor got addr %q, want :31280", fi.gotAddr)
	}
	// The dispatched request went through the real /v1 router: an unknown backend
	// yields 404 from handleBackend, proving the gateway handler (not a stub) ran.
	if fi.dispatched.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(fi.dispatched.Body)
		t.Errorf("dispatched status = %d (body %q), want 404 from /v1 router", fi.dispatched.StatusCode, b)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway Run did not return after cancel")
	}
}

func TestGatewayNoInterceptorIsFine(t *testing.T) {
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    cache.NewMemoryCache(),
		Backends: backends.NewRegistry(),
	}, Options{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return")
	}
}
