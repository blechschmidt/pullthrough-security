package upstreampool

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// manualClock is an injectable, race-safe clock for deterministic breaker tests.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *manualClock { return &manualClock{t: time.Unix(1_700_000_000, 0)} }

func (c *manualClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeDoer is a scriptable upstream.Doer. handler is consulted per request; it
// returns the response (or transport error) the test wants for that URL. Every
// requested URL is recorded in order.
type fakeDoer struct {
	mu      sync.Mutex
	urls    []string
	handler func(req upstream.Request) (*upstream.Response, error)
}

func (f *fakeDoer) Do(_ context.Context, r upstream.Request) (*upstream.Response, error) {
	f.mu.Lock()
	f.urls = append(f.urls, r.URL)
	f.mu.Unlock()
	return f.handler(r)
}

func (f *fakeDoer) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.urls))
	copy(out, f.urls)
	return out
}

// resp builds a minimal success/failure response with a readable body.
func resp(status int, body string) *upstream.Response {
	return &upstream.Response{Status: status, Body: io.NopCloser(strings.NewReader(body))}
}

// hostOf extracts the scheme://host of a URL for assertions.
func hostOf(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return u[:i+3] + rest
}

func TestFailoverOrdering(t *testing.T) {
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		switch hostOf(r.URL) {
		case "https://primary.test":
			return resp(503, "down"), nil
		case "https://mirror1.test":
			return resp(503, "down"), nil
		case "https://mirror2.test":
			return resp(200, "ok"), nil
		}
		return nil, errors.New("unexpected host")
	}}
	p, err := New(Config{
		Backend: "npm",
		Client:  doer,
		Now:     clock.now,
		Endpoints: []EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror1", URL: "https://mirror1.test"},
			{ID: "mirror2", URL: "https://mirror2.test"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/lodash/-/lodash-1.0.0.tgz"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if r.Status != 200 {
		t.Fatalf("status = %d, want 200 (served by mirror2)", r.Status)
	}
	drainClose(r.Body)

	got := doer.requested()
	want := []string{
		"https://primary.test/lodash/-/lodash-1.0.0.tgz",
		"https://mirror1.test/lodash/-/lodash-1.0.0.tgz",
		"https://mirror2.test/lodash/-/lodash-1.0.0.tgz",
	}
	if len(got) != len(want) {
		t.Fatalf("requested %d urls, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if snap := p.Snapshot(); snap.FailoverTotal != 1 {
		t.Errorf("failoverTotal = %d, want 1", snap.FailoverTotal)
	}
}

func TestPrimaryServedNoFailover(t *testing.T) {
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		return resp(200, "ok"), nil
	}}
	p, _ := New(Config{
		Backend: "pip", Client: doer, Now: clock.now,
		Endpoints: []EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror", URL: "https://mirror.test"},
		},
	})
	r, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/simple/flask/"})
	if err != nil {
		t.Fatal(err)
	}
	drainClose(r.Body)
	if got := doer.requested(); len(got) != 1 || hostOf(got[0]) != "https://primary.test" {
		t.Fatalf("expected single primary request, got %v", got)
	}
	if snap := p.Snapshot(); snap.FailoverTotal != 0 {
		t.Errorf("failoverTotal = %d, want 0", snap.FailoverTotal)
	}
}

func TestNonRetryableStatusReturnedDirectly(t *testing.T) {
	// A 404 from the primary is a legitimate answer (the mirror likely 404s too).
	// The pool must return it without failover and must not trip the breaker.
	clock := newClock()
	calls := 0
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		calls++
		return resp(404, "not found"), nil
	}}
	p, _ := New(Config{
		Backend: "npm", Client: doer, Now: clock.now,
		Endpoints: []EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror", URL: "https://mirror.test"},
		},
	})
	r, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/nope"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 404 {
		t.Fatalf("status = %d, want 404", r.Status)
	}
	drainClose(r.Body)
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no failover on 404)", calls)
	}
	if st := p.Snapshot().Endpoints[0]; st.State != StateClosed.String() {
		t.Errorf("primary state = %q, want closed", st.State)
	}
}

func TestForeignURLPassThrough(t *testing.T) {
	// A URL that maps to no endpoint base (e.g. an artifact CDN or a Docker token
	// endpoint) is passed straight through to the shared client unchanged.
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		return resp(200, "ok"), nil
	}}
	p, _ := New(Config{
		Backend: "pip", Client: doer, Now: clock.now,
		Endpoints: []EndpointConfig{{ID: "primary", URL: "https://pypi.test"}},
	})
	const cdn = "https://files.pythonhosted.test/packages/ab/cd/flask-3.0.0.tar.gz"
	r, err := p.Do(context.Background(), upstream.Request{URL: cdn})
	if err != nil {
		t.Fatal(err)
	}
	drainClose(r.Body)
	got := doer.requested()
	if len(got) != 1 || got[0] != cdn {
		t.Fatalf("foreign URL not passed through verbatim: %v", got)
	}
}

func TestTransportErrorTriggersFailover(t *testing.T) {
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		if hostOf(r.URL) == "https://primary.test" {
			return nil, errors.New("connection refused")
		}
		return resp(200, "ok"), nil
	}}
	p, _ := New(Config{
		Backend: "cargo", Client: doer, Now: clock.now,
		Endpoints: []EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror", URL: "https://mirror.test"},
		},
	})
	r, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/api/v1/crates/serde/1.0.0/download"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if r.Status != 200 {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	drainClose(r.Body)
}

func TestPerMirrorCredentialOverride(t *testing.T) {
	clock := newClock()
	var gotCreds upstream.Credentials
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		if hostOf(r.URL) == "https://primary.test" {
			return resp(503, "down"), nil
		}
		gotCreds = r.Creds
		return resp(200, "ok"), nil
	}}
	p, _ := New(Config{
		Backend: "npm", Client: doer, Now: clock.now,
		Endpoints: []EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror", URL: "https://mirror.test", Credentials: upstream.Credentials{Token: "mirror-token"}},
		},
	})
	// Backend passes its own creds in the request; the mirror must override them.
	r, err := p.Do(context.Background(), upstream.Request{
		URL:   "https://primary.test/pkg",
		Creds: upstream.Credentials{Token: "primary-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	drainClose(r.Body)
	if gotCreds.Token != "mirror-token" {
		t.Errorf("mirror creds = %q, want mirror-token", gotCreds.Token)
	}
}

func TestRelativizeRejectsPartialHostMatch(t *testing.T) {
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		return resp(200, "ok"), nil
	}}
	p, _ := New(Config{
		Backend: "npm", Client: doer, Now: clock.now,
		Endpoints: []EndpointConfig{{ID: "primary", URL: "https://a.test"}},
	})
	// "https://a.test.evil/..." must NOT be treated as belonging to "https://a.test".
	const evil = "https://a.test.evil/x"
	r, err := p.Do(context.Background(), upstream.Request{URL: evil})
	if err != nil {
		t.Fatal(err)
	}
	drainClose(r.Body)
	if got := doer.requested(); len(got) != 1 || got[0] != evil {
		t.Fatalf("partial host match should pass through verbatim, got %v", got)
	}
}

func TestNewValidation(t *testing.T) {
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) { return resp(200, ""), nil }}
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no backend", Config{Client: doer, Endpoints: []EndpointConfig{{URL: "https://a.test"}}}},
		{"no client", Config{Backend: "x", Endpoints: []EndpointConfig{{URL: "https://a.test"}}}},
		{"no endpoints", Config{Backend: "x", Client: doer}},
		{"bad scheme", Config{Backend: "x", Client: doer, Endpoints: []EndpointConfig{{URL: "ftp://a.test"}}}},
		{"dup id", Config{Backend: "x", Client: doer, Endpoints: []EndpointConfig{{ID: "a", URL: "https://a.test"}, {ID: "a", URL: "https://b.test"}}}},
	}
	for _, tc := range cases {
		if _, err := New(tc.cfg); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
	if _, err := New(Config{Backend: "x", Client: doer, Endpoints: []EndpointConfig{{URL: "https://a.test"}}}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// ensure DefaultRetryable matches the documented contract.
func TestDefaultRetryable(t *testing.T) {
	for status, want := range map[int]bool{200: false, 304: false, 404: false, 401: false, 429: true, 500: true, 503: true} {
		if got := DefaultRetryable(status); got != want {
			t.Errorf("DefaultRetryable(%d) = %v, want %v", status, got, want)
		}
	}
}
