package git

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newPassthroughBackend builds a git Backend in pass-through mode pointed at the
// given upstream base URL.
func newPassthroughBackend(t *testing.T, baseURL string, creds upstream.Credentials, c cache.Cache, ttl time.Duration) *Backend {
	t.Helper()
	up, err := NewUpstream(UpstreamOptions{
		Name:        "gh",
		URL:         baseURL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		Credentials: creds,
	})
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	b, err := NewBackend(BackendOptions{Upstream: up, Cache: c, InfoRefsTTL: ttl, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	return b
}

func TestPassthroughInfoRefs(t *testing.T) {
	const advBody = "001e# service=git-upload-pack\n0000004895dcfa3633004da0049d3d0fa03f80589cbcaf31 refs/heads/main\x00caps\n0000"
	var gotAuth, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", ctUploadPackAdvertisement)
		_, _ = io.WriteString(w, advBody)
	}))
	defer srv.Close()

	b := newPassthroughBackend(t, srv.URL, upstream.Credentials{Token: "secret"}, nil, 0)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/o/r.git/info/refs?service=git-upload-pack", nil)
	b.ServeBackendHTTP(rr, req, "/o/r.git/info/refs")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != ctUploadPackAdvertisement {
		t.Errorf("content-type = %q", ct)
	}
	if rr.Body.String() != advBody {
		t.Errorf("body mismatch: %q", rr.Body.String())
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("upstream Authorization = %q, want Bearer secret", gotAuth)
	}
	if gotPath != "/o/r.git/info/refs" {
		t.Errorf("upstream path = %q", gotPath)
	}
	if gotQuery != "service=git-upload-pack" {
		t.Errorf("upstream query = %q", gotQuery)
	}
}

func TestPassthroughRejectsPush(t *testing.T) {
	b := newPassthroughBackend(t, "https://github.com", upstream.Credentials{}, nil, 0)

	// receive-pack endpoint.
	rr := httptest.NewRecorder()
	b.ServeBackendHTTP(rr, httptest.NewRequest(http.MethodPost, "/o/r.git/git-receive-pack", nil), "/o/r.git/git-receive-pack")
	if rr.Code != http.StatusForbidden {
		t.Errorf("receive-pack status = %d, want 403", rr.Code)
	}

	// info/refs with receive-pack service.
	rr = httptest.NewRecorder()
	b.ServeBackendHTTP(rr, httptest.NewRequest(http.MethodGet, "/o/r.git/info/refs?service=git-receive-pack", nil), "/o/r.git/info/refs")
	if rr.Code != http.StatusForbidden {
		t.Errorf("info/refs receive-pack status = %d, want 403", rr.Code)
	}
}

func TestPassthroughUploadPack(t *testing.T) {
	const reqBody = "0032want 95dcfa3633004da0049d3d0fa03f80589cbcaf31\n00000009done\n"
	const respBody = "0008NAK\nPACKDATA"
	var gotBody, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("upstream method = %s", r.Method)
		}
		gotCT = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", ctUploadPackResult)
		_, _ = io.WriteString(w, respBody)
	}))
	defer srv.Close()

	b := newPassthroughBackend(t, srv.URL, upstream.Credentials{}, nil, 0)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/o/r.git/git-upload-pack", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", ctUploadPackRequest)
	b.ServeBackendHTTP(rr, req, "/o/r.git/git-upload-pack")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if gotBody != reqBody {
		t.Errorf("forwarded body = %q, want %q", gotBody, reqBody)
	}
	if gotCT != ctUploadPackRequest {
		t.Errorf("forwarded content-type = %q", gotCT)
	}
	if rr.Body.String() != respBody {
		t.Errorf("response body = %q, want %q", rr.Body.String(), respBody)
	}
	if ct := rr.Header().Get("Content-Type"); ct != ctUploadPackResult {
		t.Errorf("response content-type = %q", ct)
	}
}

func TestPassthroughUploadPackWrongContentType(t *testing.T) {
	b := newPassthroughBackend(t, "https://github.com", upstream.Credentials{}, nil, 0)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/o/r.git/git-upload-pack", strings.NewReader("x"))
	req.Header.Set("Content-Type", "text/plain")
	b.ServeBackendHTTP(rr, req, "/o/r.git/git-upload-pack")
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", rr.Code)
	}
}

func TestPassthroughInfoRefsCaching(t *testing.T) {
	const advBody = "001e# service=git-upload-pack\n00000000"
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", ctUploadPackAdvertisement)
		_, _ = io.WriteString(w, advBody)
	}))
	defer srv.Close()

	mem := cache.NewMemoryCache()
	defer mem.Close()
	b := newPassthroughBackend(t, srv.URL, upstream.Credentials{}, mem, time.Minute)

	do := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/o/r.git/info/refs?service=git-upload-pack", nil)
		b.ServeBackendHTTP(rr, req, "/o/r.git/info/refs")
		return rr
	}

	first := do()
	if first.Code != http.StatusOK || first.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first: code=%d xcache=%q", first.Code, first.Header().Get("X-Cache"))
	}
	second := do()
	if second.Code != http.StatusOK || second.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second: code=%d xcache=%q", second.Code, second.Header().Get("X-Cache"))
	}
	if second.Body.String() != advBody {
		t.Errorf("cached body mismatch: %q", second.Body.String())
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (second served from cache)", got)
	}
}

func TestPassthroughUpstreamNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	b := newPassthroughBackend(t, srv.URL, upstream.Credentials{}, nil, 0)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/o/r.git/info/refs?service=git-upload-pack", nil)
	b.ServeBackendHTTP(rr, req, "/o/r.git/info/refs")
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestUnknownEndpoint(t *testing.T) {
	b := newPassthroughBackend(t, "https://github.com", upstream.Credentials{}, nil, 0)
	rr := httptest.NewRecorder()
	b.ServeBackendHTTP(rr, httptest.NewRequest(http.MethodGet, "/o/r.git/objects/info/packs", nil), "/o/r.git/objects/info/packs")
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestNewBackendSSHRequiresMirror(t *testing.T) {
	up, err := NewUpstream(UpstreamOptions{Name: "gh", URL: "ssh://git@github.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewBackend(BackendOptions{Upstream: up}); err == nil {
		t.Error("expected error: SSH upstream without mirror")
	}
}
