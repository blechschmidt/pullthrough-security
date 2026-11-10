package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func baseSinkCfg(name, url string) SinkConfig {
	return SinkConfig{Name: name, Kind: "webhook", URL: url}
}

func TestValidateRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no sinks", Config{}, "no sinks"},
		{"empty name", Config{Sinks: []SinkConfig{{Kind: "webhook", URL: "http://x"}}}, "empty name"},
		{"dup name", Config{Sinks: []SinkConfig{baseSinkCfg("a", "http://x"), baseSinkCfg("a", "http://y")}}, "duplicate"},
		{"bad kind", Config{Sinks: []SinkConfig{{Name: "a", Kind: "carrier-pigeon", URL: "http://x"}}}, "unknown kind"},
		{"empty url", Config{Sinks: []SinkConfig{{Name: "a", Kind: "webhook"}}}, "empty url"},
		{"non-http url", Config{Sinks: []SinkConfig{{Name: "a", Kind: "webhook", URL: "ftp://x"}}}, "http(s)"},
		{"bad severity", Config{MinSeverity: "nope", Sinks: []SinkConfig{baseSinkCfg("a", "http://x")}}, "minSeverity"},
		{
			"route undefined sink",
			Config{Sinks: []SinkConfig{baseSinkCfg("a", "http://x")}, Routes: []RouteConfig{{Sinks: []string{"b"}}}},
			"undefined sink",
		},
		{
			"route bad event type",
			Config{Sinks: []SinkConfig{baseSinkCfg("a", "http://x")}, Routes: []RouteConfig{{Sinks: []string{"a"}, EventTypes: []string{"nope"}}}},
			"unknown event type",
		},
		{
			"route empty sinks",
			Config{Sinks: []SinkConfig{baseSinkCfg("a", "http://x")}, Routes: []RouteConfig{{}}},
			"references no sinks",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateAcceptsGoodConfig(t *testing.T) {
	cfg := Config{
		MinSeverity: "high",
		Sinks: []SinkConfig{
			{Name: "hook", Kind: "webhook", URL: "https://example.com/hook"},
			{Name: "slack", Kind: "slack", URL: "https://hooks.slack.com/services/x"},
		},
		Routes: []RouteConfig{
			{Sinks: []string{"hook"}, EventTypes: []string{"policy_block", "vulnerability"}, MinSeverity: "medium"},
			{Sinks: []string{"slack"}},
		},
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestBuildImplicitCatchAllRoute(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := Build(Config{
		Workers:   2,
		QueueSize: 16,
		Sinks:     []SinkConfig{{Name: "hook", Kind: "webhook", URL: srv.URL}},
		// No routes: implicit catch-all delivers every type to every sink.
	}, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer n.Close()

	n.Emit(context.Background(), PolicyBlockEvent("npm", "b", "x@1", "denylist", "no"))
	n.Emit(context.Background(), QuarantineEvent(SeverityCritical, "npm", "b", "x@1", "CVE-1", "q"))

	waitFor(t, func() bool { return hits.Load() == 2 }, 2*time.Second)
}

// TestBuildEndToEndRetryThroughHTTP exercises the full path — Build, routing,
// the real WebhookSink, and the Notifier's retry loop — against an httptest
// server that fails twice with a 503 before succeeding.
func TestBuildEndToEndRetryThroughHTTP(t *testing.T) {
	var attempts atomic.Int64
	var bodies atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable) // retryable
			return
		}
		bodies.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := Build(Config{
		Workers:        1,
		MaxRetries:     5,
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  5 * time.Millisecond,
		Sinks:          []SinkConfig{{Name: "hook", Kind: "webhook", URL: srv.URL}},
	}, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer n.Close()

	n.Emit(context.Background(), VulnerabilityEvent(SeverityHigh, "npm", "b", "x@1", "CVE-1", "block", "bad"))

	// Gate on the notifier's own Sent counter rather than the server-side
	// handler counter: the handler increments bodies before the worker records
	// the delivery, so waiting on bodies can observe metrics mid-update. Sent==1
	// guarantees the worker finished recording the send (and its retries).
	waitFor(t, func() bool { return n.Metrics().PerSink["hook"].Sent == 1 }, 3*time.Second)
	if got := bodies.Load(); got != 1 {
		t.Errorf("server completed %d successful deliveries, want 1", got)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("server saw %d attempts, want 3 (2 failures + success)", got)
	}
	m := n.Metrics().PerSink["hook"]
	if m.Sent != 1 || m.Retries != 2 || m.Failed != 0 {
		t.Errorf("metrics = %+v, want Sent=1 Retries=2 Failed=0", m)
	}
}

func TestBuildSlackEndToEnd(t *testing.T) {
	var got atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := Build(Config{
		Sinks: []SinkConfig{{Name: "slack", Kind: "slack", URL: srv.URL, Channel: "#sec"}},
	}, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer n.Close()

	results, err := n.Test(context.Background(), "slack")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if len(results) != 1 || !results[0].OK {
		t.Errorf("slack test result = %+v", results)
	}
	if got.Load() != 1 {
		t.Errorf("slack server hits = %d, want 1", got.Load())
	}
}

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(t *testing.T, cond func() bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
