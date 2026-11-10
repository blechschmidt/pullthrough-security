package rekor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc adapts a function to the Doer interface so a test can supply a
// canned transport without a listening socket — the "fakeable transport".
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(status int, body any) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(b)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// TestHTTPClientSubmitParsesResponse confirms the HTTP client builds an intoto
// proposed entry, POSTs it to the right path, and normalizes the Rekor
// LogEntryAnon map response into a *LogEntry with its inclusion proof and SET.
func TestHTTPClientSubmitParsesResponse(t *testing.T) {
	var gotPath, gotBody string
	doer := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		resp := map[string]any{
			"abc123uuid": map[string]any{
				"logID":          "deadbeef",
				"logIndex":       int64(99),
				"body":           "Ym9keQ==",
				"integratedTime": int64(1700000000),
				"verification": map[string]any{
					"signedEntryTimestamp": "c2V0",
					"inclusionProof": map[string]any{
						"logIndex": int64(3),
						"rootHash": "aa",
						"treeSize": int64(4),
						"hashes":   []string{"bb", "cc"},
					},
				},
			},
		}
		return jsonResponse(http.StatusCreated, resp), nil
	})

	c := NewHTTPClient(HTTPConfig{URL: "https://rekor.example/", Doer: doer})
	entry, err := c.Submit(context.Background(), SubmitRequest{
		Envelope:     []byte(`{"payloadType":"x","payload":"e30=","signatures":[]}`),
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"),
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if gotPath != "/api/v1/log/entries" {
		t.Errorf("unexpected submit path %q", gotPath)
	}
	if !strings.Contains(gotBody, `"kind":"intoto"`) || !strings.Contains(gotBody, `"apiVersion":"0.0.1"`) {
		t.Errorf("proposed entry missing intoto markers: %s", gotBody)
	}
	if entry.UUID != "abc123uuid" || entry.LogIndex != 99 || entry.SET != "c2V0" {
		t.Errorf("unexpected entry: %+v", entry)
	}
	if entry.InclusionProof == nil || entry.InclusionProof.TreeSize != 4 || len(entry.InclusionProof.Hashes) != 2 {
		t.Errorf("unexpected inclusion proof: %+v", entry.InclusionProof)
	}
}

// TestHTTPClientSubmitErrorStatus confirms a non-success status is surfaced as
// an error and counted as a submission failure.
func TestHTTPClientSubmitErrorStatus(t *testing.T) {
	doer := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("bad entry"))}, nil
	})
	c := NewHTTPClient(HTTPConfig{Doer: doer})
	if _, err := c.Submit(context.Background(), SubmitRequest{Envelope: []byte("{}"), PublicKeyPEM: []byte("x")}); err == nil {
		t.Fatal("expected an error on HTTP 400")
	}
}

// TestMetricsRecordSubmission confirms submission outcomes fold into the shared
// counters (recorded by the orchestrator, uniformly across Client impls).
func TestMetricsRecordSubmission(t *testing.T) {
	m := NewMetrics()
	m.RecordSubmission(true, true)
	m.RecordSubmission(true, false)
	m.RecordSubmission(false, false)
	s := m.Snapshot()
	if s.Submissions != 2 || s.SubmissionProofs != 1 || s.SubmissionErrors != 1 {
		t.Errorf("unexpected submit metrics: %+v", s)
	}
}

// TestHTTPClientDefaultsURL confirms the default public Rekor URL is used when
// none is configured.
func TestHTTPClientDefaultsURL(t *testing.T) {
	c := NewHTTPClient(HTTPConfig{})
	if c.BaseURL() != DefaultPublicURL {
		t.Errorf("default base URL = %q, want %q", c.BaseURL(), DefaultPublicURL)
	}
}

// TestMetricsRecordVerification confirms verification outcomes fold into the
// shared counters, including a required-check failure.
func TestMetricsRecordVerification(t *testing.T) {
	m := NewMetrics()
	m.RecordVerification(Verification{InclusionVerified: true, SETVerified: true}, Options{RequireInclusionProof: true, RequireSET: true})
	m.RecordVerification(Verification{InclusionVerified: false}, Options{RequireInclusionProof: true})
	s := m.Snapshot()
	if s.Verifications != 2 || s.InclusionVerified != 1 || s.SETVerified != 1 || s.VerifyFailures != 1 {
		t.Errorf("unexpected verify metrics: %+v", s)
	}
}
