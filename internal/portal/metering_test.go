package portal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/metering"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
)

// meteredServer wires a portal with a real meter holding usage for BOTH tenants,
// so the hard-scoping of the /usage endpoint can be proven.
func meteredServer(t *testing.T) *Server {
	t.Helper()
	m := metering.New(metering.Config{Enabled: true})
	m.RecordRequest("acme", "npm", "npm")
	m.RecordTraffic("acme", 5000, true)
	m.RecordRequest("globex", "pypi", "pypi")
	m.RecordTraffic("globex", 9000, false)

	srv, err := New(Options{
		Auth:       testAuth(t),
		PathPrefix: "/portal",
		Version:    "test",
		Backends:   []onboard.Backend{{Name: "npm", Type: "npm"}},
		Metering:   m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func TestPortalUsageScopedToOwnTenant(t *testing.T) {
	srv := meteredServer(t)

	rec := do(t, srv, "/api/portal/usage?granularity=total", tokAlice)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice usage = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	var rep metering.UsageReport
	decode(t, rec, &rep)
	if rep.Tenant != "acme" {
		t.Fatalf("report tenant = %q, want acme", rep.Tenant)
	}
	if len(rep.Totals) != 1 || rep.Totals[0].Tenant != "acme" {
		t.Fatalf("alice must see only acme: %+v", rep.Totals)
	}
	if rep.Grand.BytesServed() != 5000 {
		t.Errorf("acme served = %d, want 5000", rep.Grand.BytesServed())
	}
	// Globex's larger usage must not leak into acme's report.
	if strings.Contains(rec.Body.String(), "globex") {
		t.Errorf("globex leaked into acme's usage report: %s", rec.Body.String())
	}
}

func TestPortalUsageCannotOverrideTenant(t *testing.T) {
	srv := meteredServer(t)
	// Even if the caller injects ?tenant=globex, the handler forces the identity's
	// own tenant (acme), so the override is ignored.
	rec := do(t, srv, "/api/portal/usage?tenant=globex&granularity=total", tokAlice)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var rep metering.UsageReport
	decode(t, rec, &rep)
	if rep.Tenant != "acme" {
		t.Fatalf("tenant override leaked: report tenant = %q, want acme", rep.Tenant)
	}
	for _, tot := range rep.Totals {
		if tot.Tenant != "acme" {
			t.Fatalf("non-acme usage present: %+v", tot)
		}
	}
}

func TestPortalUsageDisabled(t *testing.T) {
	// A server without a metering source reports the surface as unavailable.
	srv, err := New(Options{Auth: testAuth(t), PathPrefix: "/portal", Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := do(t, srv, "/api/portal/usage", tokAlice)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("usage without source = %d, want 404", rec.Code)
	}
}
