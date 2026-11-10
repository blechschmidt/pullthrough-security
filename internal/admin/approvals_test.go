package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
)

func newApprovalsService(t *testing.T) *approvals.Service {
	t.Helper()
	s, err := approvals.New(approvals.Config{Enabled: true, RequiredApprovers: 1},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("approvals.New: %v", err)
	}
	return s
}

func TestApprovalsEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp approvalsStatusResponse
	if code := getJSON(t, srv, "/admin/api/approvals", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Error("expected disabled when no approvals service wired")
	}
}

func TestApprovalsListApproveDeny(t *testing.T) {
	svc := newApprovalsService(t)
	// Open two pending reviews via the pull-path consult.
	svc.Consult(context.Background(), approvals.Scope{
		Tenant: "acme", Ecosystem: "npm", Coordinate: "evil@1.0.0", Gate: "malfeed", Reason: "known malware",
	})
	svc.Consult(context.Background(), approvals.Scope{
		Tenant: "acme", Ecosystem: "pip", Coordinate: "bad@2.0.0", Gate: "vulnscan", Reason: "critical CVE",
	})

	srv := newTestServer(t, Options{Approvals: svc})

	// List pending.
	var list approvalsStatusResponse
	if code := getJSON(t, srv, "/admin/api/approvals?status=pending", "", &list); code != http.StatusOK {
		t.Fatalf("list status = %d", code)
	}
	if !list.Enabled || len(list.Items) != 2 {
		t.Fatalf("expected 2 pending items, got enabled=%v n=%d", list.Enabled, len(list.Items))
	}
	target := list.Items[0]

	// Approve requires both approver and justification.
	if rr := postJSON(t, srv, "/admin/api/approvals/approve", `{"id":"`+target.ID+`"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("approve without approver status = %d, want 400", rr.Code)
	}
	if rr := postJSON(t, srv, "/admin/api/approvals/approve",
		`{"id":"`+target.ID+`","approver":"alice","justification":"triaged"}`); rr.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}

	// The grant is now active.
	var active approvalsStatusResponse
	if code := getJSON(t, srv, "/admin/api/approvals?status=approved", "", &active); code != http.StatusOK {
		t.Fatalf("approved list status = %d", code)
	}
	if active.Snapshot == nil || active.Snapshot.ActiveGrants != 1 {
		t.Fatalf("expected 1 active grant, snapshot=%+v", active.Snapshot)
	}

	// Deny the other pending request.
	var other string
	for _, it := range list.Items {
		if it.ID != target.ID {
			other = it.ID
		}
	}
	if rr := postJSON(t, srv, "/admin/api/approvals/deny",
		`{"id":"`+other+`","approver":"bob","justification":"genuinely bad"}`); rr.Code != http.StatusOK {
		t.Fatalf("deny status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}

	// Unknown id -> 404.
	if rr := postJSON(t, srv, "/admin/api/approvals/approve",
		`{"id":"nope","approver":"x","justification":"y"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("approve unknown id status = %d, want 404", rr.Code)
	}
}
