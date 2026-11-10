package admin

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/secops"
)

func TestSecOpsSummaryDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/secops/summary", "", nil); code != http.StatusNotFound {
		t.Fatalf("disabled summary status = %d, want 404", code)
	}
}

func TestSecOpsSummary(t *testing.T) {
	hub := secops.NewHub(secops.Options{})
	hub.Observe(notify.Event{Type: notify.EventPolicyBlock, Severity: notify.SeverityHigh, Time: time.Now(), Subject: "team-a"})
	srv := newTestServer(t, Options{SecOps: hub})

	var sum secops.Summary
	if code := getJSON(t, srv, "/admin/api/secops/summary", "", &sum); code != http.StatusOK {
		t.Fatalf("summary status = %d, want 200", code)
	}
	if sum.Window.Total != 1 || sum.Window.Blocks != 1 {
		t.Fatalf("summary window = %+v, want total/blocks 1", sum.Window)
	}
}

func TestSecOpsStreamDeliversEvent(t *testing.T) {
	hub := secops.NewHub(secops.Options{})
	srv := newTestServer(t, Options{SecOps: hub})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/admin/api/secops/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream request: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("stream content-type = %q, want text/event-stream", ct)
	}

	// Once connected, emit an event and confirm it arrives as an SSE data frame.
	// Give the handler a moment to register its subscription before emitting.
	time.Sleep(50 * time.Millisecond)
	hub.Observe(notify.Event{Type: notify.EventMaliciousBlock, Severity: notify.SeverityCritical, Time: time.Now(), Artifact: "npm evil@1"})

	sc := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !sc.Scan() {
			break
		}
		line := sc.Text()
		if strings.HasPrefix(line, "data:") && strings.Contains(line, "malfeed") {
			return // success: the verdict streamed through with its owning gate
		}
	}
	t.Fatal("did not receive the streamed malicious-block verdict")
}
