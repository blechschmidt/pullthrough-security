package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/upstreampool"
)

type stubDoer struct{}

func (stubDoer) Do(_ context.Context, _ upstream.Request) (*upstream.Response, error) {
	return &upstream.Response{Status: 200}, nil
}

func newPoolManager(t *testing.T) *upstreampool.Manager {
	t.Helper()
	p, err := upstreampool.New(upstreampool.Config{
		Backend: "npm",
		Client:  stubDoer{},
		Endpoints: []upstreampool.EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror", URL: "https://mirror.test"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := upstreampool.NewManager()
	if err := m.Add(p); err != nil {
		t.Fatal(err)
	}
	return m
}

func postJSON(t *testing.T, srv *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestUpstreamPoolStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp upstreamPoolStatusResponse
	if code := getJSON(t, srv, "/admin/api/upstreams", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Error("expected disabled when no pool manager wired")
	}
}

func TestUpstreamPoolStatusAndOverrides(t *testing.T) {
	mgr := newPoolManager(t)
	srv := newTestServer(t, Options{UpstreamPool: mgr})

	var resp upstreamPoolStatusResponse
	if code := getJSON(t, srv, "/admin/api/upstreams", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || len(resp.Pools) != 1 || resp.Pools[0].Backend != "npm" {
		t.Fatalf("unexpected status payload: %+v", resp)
	}
	if len(resp.Pools[0].Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(resp.Pools[0].Endpoints))
	}

	// Drain a mirror.
	if rec := postJSON(t, srv, "/admin/api/upstreams/drain", `{"backend":"npm","endpoint":"mirror","drained":true}`); rec.Code != http.StatusOK {
		t.Fatalf("drain code = %d: %s", rec.Code, rec.Body.String())
	}
	snap, _ := mgr.Snapshot("npm")
	drained := false
	for _, e := range snap.Endpoints {
		if e.ID == "mirror" {
			drained = e.Drained
		}
	}
	if !drained {
		t.Error("mirror not drained after admin call")
	}

	// Force the primary circuit open.
	if rec := postJSON(t, srv, "/admin/api/upstreams/circuit", `{"backend":"npm","endpoint":"primary","action":"open"}`); rec.Code != http.StatusOK {
		t.Fatalf("circuit open code = %d: %s", rec.Code, rec.Body.String())
	}
	snap, _ = mgr.Snapshot("npm")
	for _, e := range snap.Endpoints {
		if e.ID == "primary" && e.State != "open" {
			t.Errorf("primary state = %q, want open", e.State)
		}
	}

	// Invalid action and unknown endpoint are rejected.
	if rec := postJSON(t, srv, "/admin/api/upstreams/circuit", `{"backend":"npm","endpoint":"primary","action":"bogus"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bogus action code = %d, want 400", rec.Code)
	}
	if rec := postJSON(t, srv, "/admin/api/upstreams/drain", `{"backend":"npm","endpoint":"ghost","drained":true}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown endpoint code = %d, want 400", rec.Code)
	}
}

func TestUpstreamPoolOverridesDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if rec := postJSON(t, srv, "/admin/api/upstreams/drain", `{"backend":"npm","endpoint":"x","drained":true}`); rec.Code != http.StatusNotFound {
		t.Errorf("drain w/o pool code = %d, want 404", rec.Code)
	}
}
