package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// capturingServer is an httptest server that records the bodies and headers of
// the requests it receives and replies with a configurable status.
type capturingServer struct {
	t      *testing.T
	mu     sync.Mutex
	bodies [][]byte
	heads  []http.Header
	status int
}

func newCapturingServer(t *testing.T, status int) (*capturingServer, *httptest.Server) {
	cs := &capturingServer{t: t, status: status}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cs.mu.Lock()
		cs.bodies = append(cs.bodies, body)
		cs.heads = append(cs.heads, r.Header.Clone())
		st := cs.status
		cs.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(srv.Close)
	return cs, srv
}

func (cs *capturingServer) count() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.bodies)
}

func (cs *capturingServer) lastBody() []byte {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.bodies) == 0 {
		return nil
	}
	return cs.bodies[len(cs.bodies)-1]
}

func sampleEvent() Event {
	return Event{
		Type:      EventVulnerability,
		Severity:  SeverityCritical,
		Time:      time.Unix(1_700_000_000, 0).UTC(),
		Title:     "Vulnerable artifact blocked",
		Summary:   "CVE-2026-9999 affects left-pad",
		Ecosystem: "npm",
		Backend:   "npm-proxy",
		Artifact:  "left-pad@1.0.0",
		Subject:   "alice",
		Fields:    map[string]string{"advisory": "CVE-2026-9999", "action": "block"},
	}
}

func TestWebhookSinkPayloadShape(t *testing.T) {
	cs, srv := newCapturingServer(t, http.StatusOK)
	sink, err := NewWebhookSink(WebhookOptions{
		Name:    "hook",
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer abc"},
	})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}

	if err := sink.Deliver(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if cs.count() != 1 {
		t.Fatalf("expected 1 request, got %d", cs.count())
	}

	var got webhookPayload
	if err := json.Unmarshal(cs.lastBody(), &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.Type != "vulnerability" {
		t.Errorf("Type = %q, want vulnerability", got.Type)
	}
	if got.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", got.Severity)
	}
	if got.Artifact != "left-pad@1.0.0" {
		t.Errorf("Artifact = %q", got.Artifact)
	}
	if got.Source != "pullthrough-security" {
		t.Errorf("Source = %q", got.Source)
	}
	if got.Fields["advisory"] != "CVE-2026-9999" {
		t.Errorf("Fields[advisory] = %q", got.Fields["advisory"])
	}
	if got.Timestamp != "2023-11-14T22:13:20Z" {
		t.Errorf("Timestamp = %q", got.Timestamp)
	}

	// The custom header must be sent.
	cs.mu.Lock()
	auth := cs.heads[0].Get("Authorization")
	ct := cs.heads[0].Get("Content-Type")
	cs.mu.Unlock()
	if auth != "Bearer abc" {
		t.Errorf("Authorization header = %q, want Bearer abc", auth)
	}
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestSlackSinkPayloadShape(t *testing.T) {
	cs, srv := newCapturingServer(t, http.StatusOK)
	sink, err := NewSlackSink(SlackOptions{
		Name:      "slack",
		URL:       srv.URL,
		Channel:   "#alerts",
		Username:  "pullthrough",
		IconEmoji: ":shield:",
	})
	if err != nil {
		t.Fatalf("NewSlackSink: %v", err)
	}
	if err := sink.Deliver(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	var msg slackMessage
	if err := json.Unmarshal(cs.lastBody(), &msg); err != nil {
		t.Fatalf("unmarshal slack message: %v", err)
	}
	if msg.Channel != "#alerts" || msg.Username != "pullthrough" || msg.IconEmoji != ":shield:" {
		t.Errorf("slack display overrides not applied: %+v", msg)
	}
	if len(msg.Attachments) != 1 {
		t.Fatalf("want 1 attachment, got %d", len(msg.Attachments))
	}
	att := msg.Attachments[0]
	if att.Color != "#b80000" { // critical
		t.Errorf("attachment color = %q, want critical red", att.Color)
	}
	if att.Title != "Vulnerable artifact blocked" {
		t.Errorf("attachment title = %q", att.Title)
	}
	// The structured fields and coordinates must be present as attachment fields.
	found := map[string]string{}
	for _, f := range att.Fields {
		found[f.Title] = f.Value
	}
	if found["Severity"] != "critical" {
		t.Errorf("Severity field = %q", found["Severity"])
	}
	if found["advisory"] != "CVE-2026-9999" {
		t.Errorf("advisory field = %q", found["advisory"])
	}
	if found["Artifact"] != "left-pad@1.0.0" {
		t.Errorf("Artifact field = %q", found["Artifact"])
	}
}

func TestPostJSONClassifiesErrors(t *testing.T) {
	cases := []struct {
		status        int
		wantRetryable bool
		wantErr       bool
	}{
		{http.StatusOK, false, false},
		{http.StatusNoContent, false, false},
		{http.StatusBadRequest, false, true},         // 4xx permanent
		{http.StatusUnauthorized, false, true},       // 4xx permanent
		{http.StatusTooManyRequests, true, true},     // 429 retryable
		{http.StatusInternalServerError, true, true}, // 5xx retryable
		{http.StatusBadGateway, true, true},
	}
	for _, tc := range cases {
		cs, srv := newCapturingServer(t, tc.status)
		_ = cs
		err := postJSON(context.Background(), http.DefaultClient, "s", srv.URL, nil, []byte(`{}`))
		if tc.wantErr != (err != nil) {
			t.Errorf("status %d: err=%v, wantErr=%v", tc.status, err, tc.wantErr)
			continue
		}
		if err != nil && isRetryable(err) != tc.wantRetryable {
			t.Errorf("status %d: retryable=%v, want %v", tc.status, isRetryable(err), tc.wantRetryable)
		}
	}
}

func TestPostJSONTransportErrorIsRetryable(t *testing.T) {
	// A connection to an address with nothing listening is a transport failure.
	err := postJSON(context.Background(), &http.Client{Timeout: 200 * time.Millisecond},
		"s", "http://127.0.0.1:1/nothing", nil, []byte(`{}`))
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if !isRetryable(err) {
		t.Errorf("transport error should be retryable: %v", err)
	}
}

func TestSinkConstructorsValidate(t *testing.T) {
	if _, err := NewWebhookSink(WebhookOptions{URL: "http://x"}); err == nil {
		t.Error("webhook without name should error")
	}
	if _, err := NewWebhookSink(WebhookOptions{Name: "x"}); err == nil {
		t.Error("webhook without url should error")
	}
	if _, err := NewSlackSink(SlackOptions{URL: "http://x"}); err == nil {
		t.Error("slack without name should error")
	}
	if _, err := NewSlackSink(SlackOptions{Name: "x"}); err == nil {
		t.Error("slack without url should error")
	}
}
