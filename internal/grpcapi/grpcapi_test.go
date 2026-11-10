package grpcapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	connect "connectrpc.com/connect"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	securityv1 "github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1"
	"github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1/securityv1connect"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
)

// fakeBackend is a minimal Backend that records the tenant of every query it
// receives and returns a fixed set of rows. It lets the tests assert both the
// streaming behavior and the hard per-tenant scoping the service enforces.
type fakeBackend struct {
	mu        sync.Mutex
	rows      []map[string]any
	seen      []string // tenants observed, in call order
	returnErr error
}

func (b *fakeBackend) Query(q queryapi.Query) (queryapi.Result, error) {
	b.mu.Lock()
	b.seen = append(b.seen, q.Tenant)
	b.mu.Unlock()
	if b.returnErr != nil {
		return queryapi.Result{}, b.returnErr
	}
	// Honor a tenant filter so resolve() (which selects a single row) and the
	// corpus query both behave sensibly: when a tenant is set, only rows whose
	// "tenant" field matches are returned.
	var out []map[string]any
	for _, r := range b.rows {
		if q.Tenant != "" {
			if t, _ := r["tenant"].(string); t != q.Tenant {
				continue
			}
		}
		out = append(out, r)
	}
	return queryapi.Result{
		Rows:     out,
		Fields:   []string{"tenant", "coordinate", "riskScore"},
		Total:    len(out),
		Returned: len(out),
		Limit:    q.Limit,
	}, nil
}

func (b *fakeBackend) tenants() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.seen...)
}

// newTestServer spins up the Connect handler behind an httptest server. The
// injectTenant middleware simulates the admin RBAC layer: when set, it binds the
// request context to a tenant-scoped identity exactly as internal/admin's rbac
// middleware does after authenticating an OIDC caller.
func newTestServer(t *testing.T, backend Backend, injectTenant string) (securityv1connect.SecurityQueryServiceClient, func()) {
	t.Helper()
	srv := New(Config{Backend: backend, Version: "test"})
	path, handler := srv.Handler()
	mux := http.NewServeMux()
	mux.Handle(path, handler)

	var root http.Handler = mux
	if injectTenant != "" {
		root = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := &adminauth.Identity{Subject: "tester", Tenant: injectTenant, Method: "static"}
			mux.ServeHTTP(w, r.WithContext(adminauth.WithIdentity(r.Context(), id)))
		})
	}
	ts := httptest.NewServer(root)
	cli := securityv1connect.NewSecurityQueryServiceClient(ts.Client(), ts.URL)
	return cli, ts.Close
}

func TestStreamQueryCorpus(t *testing.T) {
	backend := &fakeBackend{rows: []map[string]any{
		{"tenant": "", "coordinate": "pkg:npm/a@1", "riskScore": 10},
		{"tenant": "", "coordinate": "pkg:npm/b@1", "riskScore": 20},
		{"tenant": "", "coordinate": "pkg:npm/c@1", "riskScore": 30},
	}}
	cli, stop := newTestServer(t, backend, "")
	defer stop()

	stream, err := cli.StreamQueryCorpus(context.Background(), connect.NewRequest(&securityv1.QueryRequest{Limit: 10}))
	if err != nil {
		t.Fatalf("StreamQueryCorpus: %v", err)
	}
	var rows int
	var gotSummary bool
	for stream.Receive() {
		msg := stream.Msg()
		switch k := msg.GetKind().(type) {
		case *securityv1.QueryRowOrSummary_Row:
			if gotSummary {
				t.Fatalf("received a row after the summary")
			}
			rows++
		case *securityv1.QueryRowOrSummary_Summary:
			gotSummary = true
			if got := int(k.Summary.GetReturned()); got != 3 {
				t.Fatalf("summary.returned = %d, want 3", got)
			}
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream error: %v", err)
	}
	if rows != 3 {
		t.Fatalf("streamed %d rows, want 3", rows)
	}
	if !gotSummary {
		t.Fatalf("stream did not emit a terminal summary")
	}
}

func TestTenantHardScoping(t *testing.T) {
	// A tenant-bound identity ("acme") must win over any tenant the client puts in
	// the request message ("evil"): every query the backend sees is scoped to
	// "acme". This is the per-tenant isolation the task requires.
	backend := &fakeBackend{rows: []map[string]any{
		{"tenant": "acme", "coordinate": "pkg:npm/a@1", "riskScore": 10},
		{"tenant": "evil", "coordinate": "pkg:npm/secret@1", "riskScore": 99},
	}}
	cli, stop := newTestServer(t, backend, "acme")
	defer stop()

	// QueryCorpus with a spoofed tenant.
	resp, err := cli.QueryCorpus(context.Background(), connect.NewRequest(&securityv1.QueryRequest{Tenant: "evil", Limit: 10}))
	if err != nil {
		t.Fatalf("QueryCorpus: %v", err)
	}
	if got := int(resp.Msg.GetReturned()); got != 1 {
		t.Fatalf("returned = %d, want 1 (only the acme row)", got)
	}
	for _, row := range resp.Msg.GetRows() {
		if tn, _ := row.AsMap()["tenant"].(string); tn != "acme" {
			t.Fatalf("leaked a row for tenant %q", tn)
		}
	}

	// GetRiskVerdict with a spoofed tenant.
	rv, err := cli.GetRiskVerdict(context.Background(), connect.NewRequest(&securityv1.CoordinateRequest{
		Tenant: "evil", Name: "secret",
	}))
	if err != nil {
		t.Fatalf("GetRiskVerdict: %v", err)
	}
	if rv.Msg.GetTenant() != "acme" {
		t.Fatalf("risk verdict tenant = %q, want acme", rv.Msg.GetTenant())
	}

	for _, seen := range backend.tenants() {
		if seen != "acme" {
			t.Fatalf("backend saw a query scoped to %q; the identity tenant was not enforced", seen)
		}
	}
}

func TestGlobalIdentityMayTargetTenant(t *testing.T) {
	// With no identity bound (a global admin / trusted-network call), the request
	// tenant field is honored, matching the GraphQL/MCP semantics.
	backend := &fakeBackend{rows: []map[string]any{
		{"tenant": "team-a", "coordinate": "pkg:npm/a@1", "riskScore": 10},
		{"tenant": "team-b", "coordinate": "pkg:npm/b@1", "riskScore": 20},
	}}
	cli, stop := newTestServer(t, backend, "")
	defer stop()

	resp, err := cli.QueryCorpus(context.Background(), connect.NewRequest(&securityv1.QueryRequest{Tenant: "team-b", Limit: 10}))
	if err != nil {
		t.Fatalf("QueryCorpus: %v", err)
	}
	if got := int(resp.Msg.GetReturned()); got != 1 {
		t.Fatalf("returned = %d, want 1", got)
	}
	seen := backend.tenants()
	if len(seen) == 0 || seen[len(seen)-1] != "team-b" {
		t.Fatalf("backend tenants = %v, want last query scoped to team-b", seen)
	}
}

func TestInvalidArgument(t *testing.T) {
	backend := &fakeBackend{}
	cli, stop := newTestServer(t, backend, "")
	defer stop()

	_, err := cli.GetRiskVerdict(context.Background(), connect.NewRequest(&securityv1.CoordinateRequest{}))
	if err == nil {
		t.Fatalf("expected an error for a missing name")
	}
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want invalid_argument", connect.CodeOf(err))
	}
}

func TestMetrics(t *testing.T) {
	backend := &fakeBackend{rows: []map[string]any{
		{"tenant": "", "coordinate": "pkg:npm/a@1", "riskScore": 10},
	}}
	srv := New(Config{Backend: backend})
	path, handler := srv.Handler()
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	cli := securityv1connect.NewSecurityQueryServiceClient(ts.Client(), ts.URL)

	if _, err := cli.QueryCorpus(context.Background(), connect.NewRequest(&securityv1.QueryRequest{})); err != nil {
		t.Fatalf("QueryCorpus: %v", err)
	}
	stream, err := cli.StreamQueryCorpus(context.Background(), connect.NewRequest(&securityv1.QueryRequest{}))
	if err != nil {
		t.Fatalf("StreamQueryCorpus: %v", err)
	}
	for stream.Receive() {
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream: %v", err)
	}

	snap := srv.Snapshot()
	if snap.Requests < 2 {
		t.Fatalf("Requests = %d, want >= 2", snap.Requests)
	}
	if snap.Streams != 1 {
		t.Fatalf("Streams = %d, want 1", snap.Streams)
	}
	// One row + one summary message sent on the stream.
	if snap.StreamMessages != 2 {
		t.Fatalf("StreamMessages = %d, want 2", snap.StreamMessages)
	}
	if snap.RPCCalls[rpcQueryCorpus] != 1 {
		t.Fatalf("QueryCorpus calls = %d, want 1", snap.RPCCalls[rpcQueryCorpus])
	}
}

func TestDisabled(t *testing.T) {
	if New(Config{}).Enabled() {
		t.Fatalf("a server with no backend must not be enabled")
	}
	if New(Config{}) != nil {
		t.Fatalf("New with no backend should return nil")
	}
	var s *Server
	if s.Enabled() {
		t.Fatalf("nil server must not be enabled")
	}
	if path, h := s.Handler(); path != "" || h != nil {
		t.Fatalf("nil server Handler should be empty")
	}
}
