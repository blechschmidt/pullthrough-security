package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
)

func TestRateLimitStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp rateLimitStatusResponse
	if code := getJSON(t, srv, "/admin/api/ratelimit", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if resp.Enabled {
		t.Fatal("expected disabled when no limiter is wired")
	}
}

func TestRateLimitStatusReportsSnapshot(t *testing.T) {
	lim := ratelimit.New(ratelimit.Options{
		Default: ratelimit.Policy{RPS: 10, Burst: 5, MaxConcurrent: 3},
	})
	// Generate a little activity so the snapshot is non-trivial.
	res, _ := lim.Admit(context.Background(), "team-a")
	res.Release()

	srv := newTestServer(t, Options{RateLimit: lim})
	var resp rateLimitStatusResponse
	if code := getJSON(t, srv, "/admin/api/ratelimit", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if !resp.Enabled || resp.Snapshot == nil {
		t.Fatal("expected enabled status with a snapshot")
	}
	if resp.Snapshot.Allowed != 1 {
		t.Fatalf("allowed = %d, want 1", resp.Snapshot.Allowed)
	}
	if len(resp.Snapshot.Tenants) != 1 || resp.Snapshot.Tenants[0].Tenant != "team-a" {
		t.Fatalf("expected one tenant row for team-a, got %+v", resp.Snapshot.Tenants)
	}
}

func putJSON(t *testing.T, srv *Server, path string, body any) (int, map[string]any) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(buf))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out
}

func TestRateLimitSetTenantPolicy(t *testing.T) {
	lim := ratelimit.New(ratelimit.Options{})
	srv := newTestServer(t, Options{RateLimit: lim})

	code, _ := putJSON(t, srv, "/admin/api/ratelimit/policy", rateLimitSetPolicyRequest{
		Tenant: "team-a",
		Policy: ratelimit.Policy{RPS: 1, Burst: 1},
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	// The update must take effect: team-a now has a burst-1 bucket.
	if _, dec := lim.Admit(context.Background(), "team-a"); !dec.Allowed {
		t.Fatal("first admit after policy set should succeed")
	}
	if _, dec := lim.Admit(context.Background(), "team-a"); dec.Allowed {
		t.Fatal("second admit should be throttled by the new burst-1 policy")
	}
}

func TestRateLimitSetGlobalPolicy(t *testing.T) {
	lim := ratelimit.New(ratelimit.Options{})
	srv := newTestServer(t, Options{RateLimit: lim})

	code, _ := putJSON(t, srv, "/admin/api/ratelimit/policy", rateLimitSetPolicyRequest{
		Global: true,
		Policy: ratelimit.Policy{MaxConcurrent: 1},
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	r1, d1 := lim.Admit(context.Background(), "any")
	if !d1.Allowed {
		t.Fatal("first admit should succeed under global cap 1")
	}
	if _, d2 := lim.Admit(context.Background(), "other"); d2.Allowed {
		t.Fatal("second admit should be blocked by the global concurrency cap")
	}
	r1.Release()
}

func TestRateLimitSetPolicyValidation(t *testing.T) {
	lim := ratelimit.New(ratelimit.Options{})
	srv := newTestServer(t, Options{RateLimit: lim})

	// Negative value is rejected with 400.
	code, _ := putJSON(t, srv, "/admin/api/ratelimit/policy", rateLimitSetPolicyRequest{
		Tenant: "team-a",
		Policy: ratelimit.Policy{RPS: -1},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("negative policy status = %d, want 400", code)
	}

	// Missing tenant (and not global) is a 400.
	code, _ = putJSON(t, srv, "/admin/api/ratelimit/policy", rateLimitSetPolicyRequest{
		Policy: ratelimit.Policy{RPS: 1},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("missing-tenant status = %d, want 400", code)
	}
}

func TestRateLimitSetPolicyNotEnabled(t *testing.T) {
	srv := newTestServer(t, Options{}) // no limiter
	code, _ := putJSON(t, srv, "/admin/api/ratelimit/policy", rateLimitSetPolicyRequest{
		Tenant: "team-a",
		Policy: ratelimit.Policy{RPS: 1},
	})
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when rate limiting is disabled", code)
	}
}
