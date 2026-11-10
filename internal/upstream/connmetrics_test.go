package upstream

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// drain issues one request through c and fully reads+closes the body so the
// connection can be returned to the keep-alive pool for reuse.
func drain(t *testing.T, c *Client, url string) {
	t.Helper()
	resp, err := c.Do(context.Background(), Request{URL: url})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func TestConnMetricsReuse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	cm := &ConnMetrics{}
	c, err := New(Options{ConnMetrics: cm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 8
	for i := 0; i < n; i++ {
		drain(t, c, srv.URL)
	}

	s := cm.Snapshot()
	if s.Acquired != n {
		t.Errorf("Acquired = %d, want %d", s.Acquired, n)
	}
	// Sequential requests over a keep-alive pool should dial once and reuse the
	// connection for every subsequent request.
	if s.Dials != 1 {
		t.Errorf("Dials = %d, want 1 (connection should be reused)", s.Dials)
	}
	if s.Reused != n-1 {
		t.Errorf("Reused = %d, want %d", s.Reused, n-1)
	}
	if got := s.ReuseRatio(); got < 0.8 {
		t.Errorf("ReuseRatio = %.3f, want >= 0.8", got)
	}
	if s.DialCount != 1 || s.DialSeconds <= 0 {
		t.Errorf("DialCount/DialSeconds = %d/%.6f, want 1 and > 0", s.DialCount, s.DialSeconds)
	}
	if s.Open < 1 {
		t.Errorf("Open = %d, want >= 1 while the pooled connection is live", s.Open)
	}
}

func TestConnMetricsDisableKeepAlivesChurns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	cm := &ConnMetrics{}
	c, err := New(Options{ConnMetrics: cm, DisableKeepAlives: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 5
	for i := 0; i < n; i++ {
		drain(t, c, srv.URL)
	}

	s := cm.Snapshot()
	// With keep-alives disabled every request dials a fresh connection and never
	// reuses one — the connection-churn signal the perfguard conn-reuse gate
	// exists to catch. Dials and Reused are recorded synchronously during each
	// request, so they are exact.
	if s.Dials != n {
		t.Errorf("Dials = %d, want %d (no reuse with keep-alives disabled)", s.Dials, n)
	}
	if s.Reused != 0 {
		t.Errorf("Reused = %d, want 0", s.Reused)
	}
	// The transport tears a connection down asynchronously after its body closes,
	// so poll briefly for the close accounting to settle rather than asserting it
	// synchronously (which races the transport's read loop).
	deadline := time.Now().Add(2 * time.Second)
	for cm.Snapshot().Closed < int64(n) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := cm.Snapshot().Closed; got != int64(n) {
		t.Errorf("Closed = %d, want %d (each connection torn down after its request)", got, n)
	}
	if got := cm.Snapshot().Open; got != 0 {
		t.Errorf("Open = %d, want 0 after all churned connections closed", got)
	}
}

func TestConnMetricsNilSnapshot(t *testing.T) {
	var cm *ConnMetrics
	if got := cm.Snapshot().Acquired; got != 0 {
		t.Errorf("nil ConnMetrics snapshot Acquired = %d, want 0", got)
	}
}
