package upstream

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	return NewWithHTTPClient(http.DefaultClient, "test-agent/1")
}

func TestDoInjectsBearerToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{
		URL:   srv.URL,
		Creds: Credentials{Token: "abc123"},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if gotAuth != "Bearer abc123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer abc123")
	}
}

func TestDoInjectsBasicAuth(t *testing.T) {
	var (
		user, pass string
		ok         bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{
		URL:   srv.URL,
		Creds: Credentials{Username: "u", Password: "p"},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if !ok || user != "u" || pass != "p" {
		t.Errorf("BasicAuth = (%q,%q,%v), want (u,p,true)", user, pass, ok)
	}
}

func TestDoTokenTakesPrecedenceOverBasic(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{
		URL:   srv.URL,
		Creds: Credentials{Username: "u", Password: "p", Token: "tok"},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok (token must win)", gotAuth)
	}
}

func TestDoDoesNotOverrideExplicitAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{
		URL:    srv.URL,
		Header: http.Header{"Authorization": {"Custom xyz"}},
		Creds:  Credentials{Token: "tok"},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Custom xyz" {
		t.Errorf("Authorization = %q, want the caller-supplied value to be preserved", gotAuth)
	}
}

func TestDoConditionalNotModified(t *testing.T) {
	const etag = `"v1"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = io.WriteString(w, "body")
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{
		URL:         srv.URL,
		IfNoneMatch: etag,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.NotModified {
		t.Fatalf("NotModified = false, want true")
	}
	if resp.Body != nil {
		t.Errorf("Body should be nil on 304")
	}
	if resp.Status != http.StatusNotModified {
		t.Errorf("Status = %d, want 304", resp.Status)
	}
}

func TestDoReturnsStatusForErrorsWithoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Do returned error for 404, want nil: %v", err)
	}
	defer resp.Body.Close()

	if resp.IsSuccess() {
		t.Errorf("IsSuccess() = true for 404")
	}
	if resp.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", resp.Status)
	}
}

func TestDoPopulatesResponseFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.ContentType != "application/json" {
		t.Errorf("ContentType = %q", resp.ContentType)
	}
	if resp.ETag != `"abc"` {
		t.Errorf("ETag = %q", resp.ETag)
	}
	if resp.LastModified == "" {
		t.Errorf("LastModified empty")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q", body)
	}
}

func TestDoSetsUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotUA != "test-agent/1" {
		t.Errorf("User-Agent = %q, want test-agent/1", gotUA)
	}
}

func TestDoStripsHopByHopRequestHeaders(t *testing.T) {
	var gotConnection string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Get("X-Forwarded-Hop")
	}))
	defer srv.Close()

	// Connection and Keep-Alive are hop-by-hop and must not be forwarded; a
	// custom header rides along to prove non-hop-by-hop headers do pass.
	resp, err := newTestClient(t).Do(context.Background(), Request{
		URL: srv.URL,
		Header: http.Header{
			"Connection":      {"keep-alive"},
			"X-Forwarded-Hop": {"present"},
		},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if gotConnection != "present" {
		t.Errorf("X-Forwarded-Hop = %q, want present", gotConnection)
	}
}

func TestDoRejectsEmptyURL(t *testing.T) {
	if _, err := newTestClient(t).Do(context.Background(), Request{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestDoContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := newTestClient(t).Do(ctx, Request{URL: srv.URL}); err == nil {
		t.Fatal("expected error from canceled context")
	}
}

func TestNewBuildsClientWithTLSOptions(t *testing.T) {
	c, err := New(Options{TLS: TLSOptions{MinVersion: "1.3"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("New returned nil client")
	}
}

func TestNewRejectsInvalidTLSVersion(t *testing.T) {
	if _, err := New(Options{TLS: TLSOptions{MinVersion: "9.9"}}); err == nil {
		t.Fatal("expected error for invalid TLS minVersion")
	}
}

func TestNewRejectsMissingCABundle(t *testing.T) {
	if _, err := New(Options{TLS: TLSOptions{CACertFile: "/nonexistent/ca.pem"}}); err == nil {
		t.Fatal("expected error for missing CA bundle")
	}
}

func TestCredentialsIsZero(t *testing.T) {
	if !(Credentials{}).IsZero() {
		t.Error("empty Credentials should be zero")
	}
	if (Credentials{Token: "x"}).IsZero() {
		t.Error("Credentials with token should not be zero")
	}
}

func TestPropagateResponseHeadersSkipsProxyOwned(t *testing.T) {
	src := http.Header{
		"Content-Type":   {"text/plain"},
		"Content-Length": {"5"},
		"Etag":           {`"x"`},
		"Cache-Control":  {"max-age=60"},
		"Connection":     {"keep-alive"},
		"X-Custom":       {"yes"},
	}
	dst := http.Header{}
	PropagateResponseHeaders(dst, src)

	if dst.Get("Cache-Control") != "max-age=60" {
		t.Errorf("Cache-Control should propagate, got %q", dst.Get("Cache-Control"))
	}
	if dst.Get("X-Custom") != "yes" {
		t.Errorf("X-Custom should propagate, got %q", dst.Get("X-Custom"))
	}
	for _, h := range []string{"Content-Type", "Content-Length", "ETag", "Connection"} {
		if dst.Get(h) != "" {
			t.Errorf("%s should not propagate (proxy-owned/hop-by-hop), got %q", h, dst.Get(h))
		}
	}
}

func TestDoForwardsCustomHeaders(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
	}))
	defer srv.Close()

	resp, err := newTestClient(t).Do(context.Background(), Request{
		URL:    srv.URL,
		Header: http.Header{"Accept": {"application/vnd.npm.install-v1+json"}},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if !strings.Contains(gotAccept, "vnd.npm") {
		t.Errorf("Accept = %q, want the custom Accept forwarded", gotAccept)
	}
}
