package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

func TestConfigDriftEndpoint(t *testing.T) {
	cfg := config.Default()
	svc := config.NewService("", &cfg) // no file: defaults-only, never drifts
	srv := newTestServer(t, Options{Config: svc})

	var st config.DriftStatus
	code := getJSON(t, srv, "/admin/api/config/drift", "", &st)
	if code != http.StatusOK {
		t.Fatalf("drift endpoint returned %d", code)
	}
	if st.Drifted {
		t.Fatalf("defaults-only process must not report drift: %+v", st)
	}
	if st.RunningConfigHash == "" {
		t.Fatalf("expected a running fingerprint")
	}
}

func TestConfigValidateLiveEndpoint(t *testing.T) {
	cfg := config.Default()
	svc := config.NewService("", &cfg)
	srv := newTestServer(t, Options{Config: svc})

	var rep config.Report
	code := getJSON(t, srv, "/admin/api/config/validate", "", &rep)
	if code != http.StatusOK {
		t.Fatalf("validate endpoint returned %d", code)
	}
	if rep.Errors != 0 {
		t.Fatalf("the default config must validate without errors: %+v", rep.Issues)
	}
}

func TestConfigValidateCandidateEndpoint(t *testing.T) {
	cfg := config.Default()
	svc := config.NewService("", &cfg)
	srv := newTestServer(t, Options{Config: svc})

	// A candidate with a typo'd key must be reported as an error.
	body, _ := json.Marshal(map[string]string{"content": "server:\n  htpAddr: \":9090\"\n"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/config/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("candidate validate returned %d: %s", rec.Code, rec.Body.String())
	}
	var rep config.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.OK || rep.Errors == 0 {
		t.Fatalf("expected the typo'd candidate to fail validation: %+v", rep.Issues)
	}
}

func TestConfigEndpointsAbsentWhenUnwired(t *testing.T) {
	srv := newTestServer(t, Options{}) // no Config service
	if code := getJSON(t, srv, "/admin/api/config/drift", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when config service is absent, got %d", code)
	}
}
