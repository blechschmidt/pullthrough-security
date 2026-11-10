package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
)

func newDepFirewallService(t *testing.T) *depfirewall.Service {
	t.Helper()
	s, err := depfirewall.NewService(depfirewall.Config{
		DefaultAction: depfirewall.ActionAllow,
		Rules:         []depfirewall.Rule{{Ecosystem: "npm", Name: "left-pad", Pinned: []string{"1.3.0"}}},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return s
}

func TestDepFirewallEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/api/depfirewall", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when no firewall wired", rec.Code)
	}
}

func TestDepFirewallStatusAndCRUD(t *testing.T) {
	svc := newDepFirewallService(t)
	srv := newTestServer(t, Options{DepFirewall: svc})

	// Status lists the seeded global rule.
	var resp depFirewallResponse
	if code := getJSON(t, srv, "/admin/api/depfirewall", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || resp.GlobalRules != 1 || len(resp.Rules) != 1 {
		t.Fatalf("unexpected status: %+v", resp)
	}

	// Create a new rule via the admin API.
	if rr := postJSON(t, srv, "/admin/api/depfirewall/rules",
		`{"ecosystem":"pip","name":"requests","ranges":[">=2.20.0 <3.0.0"]}`); rr.Code != http.StatusOK {
		t.Fatalf("set rule status = %d (%s)", rr.Code, rr.Body.String())
	}
	if d := svc.Check("", depfirewall.Coordinate{Ecosystem: "pip", Name: "requests", Version: "2.19.0"}); !d.Blocked {
		t.Fatalf("expected the new rule to block 2.19.0, got %+v", d)
	}

	// A malformed range is rejected with 400.
	if rr := postJSON(t, srv, "/admin/api/depfirewall/rules",
		`{"ecosystem":"npm","name":"bad","ranges":[">=not-a-version"]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed range status = %d, want 400", rr.Code)
	}

	// Set the default action to deny-by-default.
	if rr := postJSON(t, srv, "/admin/api/depfirewall/default", `{"action":"block"}`); rr.Code != http.StatusOK {
		t.Fatalf("default action status = %d (%s)", rr.Code, rr.Body.String())
	}
	if d := svc.Check("", depfirewall.Coordinate{Ecosystem: "npm", Name: "ungoverned", Version: "1.0.0"}); !d.Blocked {
		t.Fatalf("deny-by-default should block ungoverned coordinate, got %+v", d)
	}

	// Delete the seeded rule.
	if rr := postJSON(t, srv, "/admin/api/depfirewall/rules/delete",
		`{"ecosystem":"npm","name":"left-pad"}`); rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d (%s)", rr.Code, rr.Body.String())
	}
	if svc.DeleteRule("", "npm", "left-pad") {
		t.Fatalf("rule should already have been deleted by the API")
	}
}

func TestDepFirewallImport(t *testing.T) {
	svc, err := depfirewall.NewService(depfirewall.Config{DefaultAction: depfirewall.ActionBlock})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	srv := newTestServer(t, Options{DepFirewall: svc})

	lock := `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`
	req := httptest.NewRequest(http.MethodPost,
		"/admin/api/depfirewall/import?tenant=team&format=package-lock.json", strings.NewReader(lock))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status = %d (%s)", rec.Code, rec.Body.String())
	}

	if d := svc.Check("team", depfirewall.Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.1"}); !d.Blocked {
		t.Fatalf("imported lockfile should block a non-lockfile version, got %+v", d)
	}
	if d := svc.Check("team", depfirewall.Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}); d.Blocked {
		t.Fatalf("imported lockfile should allow the resolved version, got %+v", d)
	}
}
