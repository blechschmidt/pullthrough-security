package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// capturingEmitter records emitted events for assertions.
type capturingEmitter struct{ events []notify.Event }

func (c *capturingEmitter) Emit(_ context.Context, ev notify.Event) { c.events = append(c.events, ev) }

func newAnomalyGateway(t *testing.T, engine *anomaly.Engine, emitter notify.Emitter) *Gateway {
	t.Helper()
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    cache.NewMemoryCache(),
		Backends: backends.NewRegistry(),
		Anomaly:  engine,
		Notify:   emitter,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func anomalyReq(tenant, identity string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/npm/@scope/pkg/-/pkg-1.0.0.tgz", nil)
	if tenant != "" || identity != "" {
		p := &auth.Principal{Team: tenant, Subject: identity}
		r = r.WithContext(auth.WithPrincipal(r.Context(), p))
	}
	return r
}

func resolvedFor(name string) *backends.Resolved {
	return &backends.Resolved{
		Coordinate: backends.Coordinate{Name: name, Version: "1.0.0"},
		CacheKey:   name,
	}
}

func TestGateAnomalyAdmitsWhenNominal(t *testing.T) {
	eng, err := anomaly.New(anomaly.Config{Enabled: true, BlockLevel: anomaly.LevelHigh})
	if err != nil {
		t.Fatal(err)
	}
	g := newAnomalyGateway(t, eng, nil)
	rr := httptest.NewRecorder()
	if !g.gateAnomaly(rr, anomalyReq("acme", "ci"), "npm", "npm") {
		t.Fatalf("a cold scope must be admitted")
	}
}

func TestObserveAndSoftBlockEnumeration(t *testing.T) {
	emit := &capturingEmitter{}
	eng, err := anomaly.New(anomaly.Config{
		Enabled:    true,
		Window:     time.Minute,
		BlockLevel: anomaly.LevelHigh,
		Tunables: anomaly.Tunables{
			FanoutWarn: 1000, FanoutHigh: 2000, // keep fan-out quiet
			NewNamespaceWarn: 1000, NewNamespaceHigh: 2000,
			OffHoursWarn: 1000, OffHoursHigh: 2000,
			EnumerationWarn: 5, EnumerationHigh: 10,
			EgressZWarn: 3, EgressZHigh: 6,
		},
		AlertCooldown: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	g := newAnomalyGateway(t, eng, emit)

	// Drive a burst of 404 enumeration from one identity.
	for i := 0; i < 12; i++ {
		g.observeAnomaly(anomalyReq("acme", "attacker"), "npm", "npm", resolvedFor("ghost-"+string(rune('a'+i))), 0, true)
	}

	// The scope should now be in a block standing, and the next request is
	// soft-blocked with a 429.
	rr := httptest.NewRecorder()
	if g.gateAnomaly(rr, anomalyReq("acme", "attacker"), "npm", "npm") {
		t.Fatalf("expected the enumerating identity to be soft-blocked")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("X-Anomaly-Decision") != "block" {
		t.Fatalf("expected X-Anomaly-Decision: block header")
	}

	// At least one anomaly notification should have been emitted.
	var anomalyEvents int
	for _, ev := range emit.events {
		if ev.Type == notify.EventAnomaly {
			anomalyEvents++
		}
	}
	if anomalyEvents == 0 {
		t.Fatalf("expected an anomaly notification to be emitted")
	}

	// A different identity in the same tenant must not be blocked.
	rr2 := httptest.NewRecorder()
	if !g.gateAnomaly(rr2, anomalyReq("acme", "innocent"), "npm", "npm") {
		t.Fatalf("an unrelated identity must not be soft-blocked")
	}
}

func TestGateAnomalyNilEngine(t *testing.T) {
	g := newAnomalyGateway(t, nil, nil)
	rr := httptest.NewRecorder()
	if !g.gateAnomaly(rr, anomalyReq("acme", "ci"), "npm", "npm") {
		t.Fatalf("nil engine must admit")
	}
	// observeAnomaly must be a safe no-op with a nil engine.
	g.observeAnomaly(anomalyReq("acme", "ci"), "npm", "npm", resolvedFor("pkg"), 10, false)
}

func TestNamespaceFor(t *testing.T) {
	cases := []struct{ eco, name, want string }{
		{"npm", "@scope/pkg", "@scope"},
		{"go", "github.com/org/mod", "github.com/org"},
		{"maven", "com.example:artifact", "com.example"},
		{"pip", "requests", ""},
		{"npm", "", ""},
	}
	for _, tc := range cases {
		if got := namespaceFor(tc.eco, tc.name); got != tc.want {
			t.Fatalf("namespaceFor(%q,%q) = %q, want %q", tc.eco, tc.name, got, tc.want)
		}
	}
}
