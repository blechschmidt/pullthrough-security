package admin

import (
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/license"
)

func TestLicenseStatusEndpoint(t *testing.T) {
	svc, err := license.NewService(license.Config{
		Base:           license.PolicyConfig{Allow: []string{"MIT"}, Deny: []string{"@strong-copyleft"}},
		DriftDetection: true,
	}, nil)
	if err != nil {
		t.Fatalf("license.NewService: %v", err)
	}
	// Drive one denied decision so the metrics and recent list are populated.
	svc.Evaluate("", []license.Component{{Ecosystem: "npm", Name: "x", Version: "1.0.0", Expression: "GPL-3.0-only", Primary: true}})

	srv := newTestServer(t, Options{License: svc})

	var resp struct {
		Enabled bool `json:"enabled"`
		Metrics *struct {
			Denied int64 `json:"denied"`
		} `json:"metrics"`
		Policy *struct {
			Action string `json:"action"`
		} `json:"policy"`
		Decisions []struct {
			Code string `json:"code"`
		} `json:"decisions"`
	}
	if code := getJSON(t, srv, "/admin/api/licenses", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !resp.Enabled || resp.Metrics == nil || resp.Metrics.Denied != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Policy == nil || resp.Policy.Action != "block" {
		t.Errorf("policy summary action = %+v", resp.Policy)
	}
	if len(resp.Decisions) != 1 || resp.Decisions[0].Code != "denied" {
		t.Errorf("decisions = %+v", resp.Decisions)
	}
}

func TestLicenseStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp struct {
		Enabled bool `json:"enabled"`
	}
	if code := getJSON(t, srv, "/admin/api/licenses", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if resp.Enabled {
		t.Error("license should report disabled when no inspector is wired")
	}
}
