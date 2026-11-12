package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/intercept"
)

// fakeIntercept is an InterceptInspector with a fixed status.
type fakeIntercept struct{}

func (fakeIntercept) Status() intercept.Status {
	return intercept.Status{
		ForwardProxy: ":3128",
		NATHTTPS:     ":8443",
		Routes: []intercept.Rule{
			{Rule: "deb.debian.org/debian", Upstream: "apt"},
			{Rule: "pypi.org", Upstream: "pip"},
		},
		HostNames: []string{"deb.debian.org", "pypi.org"},
		CASubject: "CN=Test Intercept CA",
	}
}

func (fakeIntercept) CACertPEM() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
}

func TestInterceptEndpoints(t *testing.T) {
	srv := newTestServer(t, Options{Intercept: fakeIntercept{}})

	var resp interceptResponse
	if code := getJSON(t, srv, "/admin/api/intercept", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !resp.Enabled || resp.ForwardProxy != ":3128" || resp.NATHTTPS != ":8443" || len(resp.Routes) != 2 ||
		resp.Routes[0].Rule != "deb.debian.org/debian" || resp.Routes[0].Upstream != "apt" {
		t.Fatalf("status = %+v", resp)
	}

	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	if rec := get("/admin/api/intercept?format=hosts"); rec.Code != http.StatusOK || rec.Body.String() != "deb.debian.org\npypi.org\n" {
		t.Errorf("hosts: %d %q", rec.Code, rec.Body)
	}
	if rec := get("/admin/api/intercept?format=hosts&address=10.0.0.5"); rec.Body.String() != "10.0.0.5\tdeb.debian.org\n10.0.0.5\tpypi.org\n" {
		t.Errorf("hosts-file lines: %q", rec.Body)
	}
	if rec := get("/admin/api/intercept?format=yaml"); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown format: %d", rec.Code)
	}
	rec := get("/admin/api/intercept/ca.crt")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "-----BEGIN CERTIFICATE-----") ||
		rec.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Errorf("CA: %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
}

func TestInterceptEndpointsWhenDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp interceptResponse
	if code := getJSON(t, srv, "/admin/api/intercept", "", &resp); code != http.StatusOK || resp.Enabled {
		t.Fatalf("status = %d, %+v", code, resp)
	}
	for _, path := range []string{"/admin/api/intercept/ca.crt", "/admin/api/intercept?format=hosts"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s with interception disabled: %d, want 404", path, rec.Code)
		}
	}
}

// The interception status is a read: a viewer may see it; the CA it serves is a
// certificate, not a secret.
func TestInterceptEndpointsNeedOnlyRead(t *testing.T) {
	for _, path := range []string{"/api/intercept", "/api/intercept/ca.crt"} {
		if got := requiredCapability(http.MethodGet, path); got != requiredCapability(http.MethodGet, "/api/downloads") {
			t.Errorf("GET %s requires %v", path, got)
		}
	}
}
