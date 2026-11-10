package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// mockHEC is a minimal Splunk HEC receiver for tests. It records the decoded
// event envelopes and the Authorization header, and can be told to fail a
// number of times before succeeding.
type mockHEC struct {
	mu        sync.Mutex
	envelopes []hecEnvelope
	authSeen  string
	failFirst int
	hits      int
}

func (m *mockHEC) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits++
		m.authSeen = r.Header.Get("Authorization")
		fail := m.hits <= m.failFirst
		m.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		dec := json.NewDecoder(bytes.NewReader(body))
		m.mu.Lock()
		for {
			var env hecEnvelope
			if err := dec.Decode(&env); err != nil {
				break
			}
			m.envelopes = append(m.envelopes, env)
		}
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	})
}

func (m *mockHEC) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.envelopes)
}

func TestHECSinkBatchDelivery(t *testing.T) {
	mock := &mockHEC{}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	sink, err := NewHECSink(HECOptions{
		Name:       "splunk",
		URL:        srv.URL,
		Token:      "secret-token",
		Index:      "security",
		SourceType: "pts:test",
	})
	if err != nil {
		t.Fatal(err)
	}
	batch := []Event{sampleEvent(SeverityHigh), sampleEvent(SeverityCritical)}
	if err := sink.DeliverBatch(context.Background(), batch); err != nil {
		t.Fatalf("DeliverBatch: %v", err)
	}
	if mock.count() != 2 {
		t.Fatalf("received %d envelopes, want 2", mock.count())
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if mock.authSeen != "Splunk secret-token" {
		t.Fatalf("auth header = %q, want 'Splunk secret-token'", mock.authSeen)
	}
	env := mock.envelopes[0]
	if env.Index != "security" || env.SourceType != "pts:test" {
		t.Fatalf("envelope metadata wrong: %+v", env)
	}
	if env.Event["severity"] != "high" {
		t.Fatalf("event severity = %v, want high", env.Event["severity"])
	}
	if env.Event["product"] != "pullthrough-security" {
		t.Fatalf("event product = %v", env.Event["product"])
	}
	if env.Time <= 0 {
		t.Fatalf("envelope time not set: %v", env.Time)
	}
}

func TestHECSinkRetryableAndPermanent(t *testing.T) {
	// 503 is retryable.
	mock := &mockHEC{failFirst: 1}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()
	sink, _ := NewHECSink(HECOptions{Name: "s", URL: srv.URL, Token: "t"})
	err := sink.DeliverBatch(context.Background(), []Event{sampleEvent(SeverityHigh)})
	if !isRetryable(err) {
		t.Fatalf("503 should be retryable, got %v", err)
	}

	// 400 is permanent.
	perm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer perm.Close()
	sink2, _ := NewHECSink(HECOptions{Name: "s", URL: perm.URL, Token: "t"})
	err2 := sink2.DeliverBatch(context.Background(), []Event{sampleEvent(SeverityHigh)})
	if err2 == nil || isRetryable(err2) {
		t.Fatalf("400 should be a permanent error, got %v", err2)
	}
}

func TestHECSinkEndToEndViaForwarder(t *testing.T) {
	mock := &mockHEC{}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()
	sink, _ := NewHECSink(HECOptions{Name: "splunk", URL: srv.URL, Token: "t"})

	f := New(Options{
		Sinks:        []Sink{sink},
		BatchSize:    100,
		BatchTimeout: 10 * time.Millisecond,
	})
	defer f.Close()

	for i := 0; i < 3; i++ {
		f.Emit(sampleEvent(SeverityHigh))
	}
	waitFor(t, 2*time.Second, func() bool { return mock.count() == 3 })
}

func TestNormalizeHECURL(t *testing.T) {
	cases := map[string]string{
		"https://splunk:8088":                    "https://splunk:8088/services/collector/event",
		"https://splunk:8088/":                   "https://splunk:8088/services/collector/event",
		"https://splunk:8088/services/collector": "https://splunk:8088/services/collector",
		"http://host/custom/path":                "http://host/custom/path",
	}
	for in, want := range cases {
		if got := normalizeHECURL(in); got != want {
			t.Errorf("normalizeHECURL(%q) = %q, want %q", in, got, want)
		}
	}
}
