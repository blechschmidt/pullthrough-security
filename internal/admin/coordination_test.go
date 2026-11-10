package admin

import (
	"context"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/coord"
)

// fakeCoordination is a stub CoordinationInspector for the admin handler tests.
type fakeCoordination struct {
	enabled bool
	snap    coord.Snapshot
	holders []coord.Leaseholder
}

func (f *fakeCoordination) Enabled() bool            { return f.enabled }
func (f *fakeCoordination) NodeID() string           { return f.snap.NodeID }
func (f *fakeCoordination) Snapshot() coord.Snapshot { return f.snap }
func (f *fakeCoordination) Leaseholders(context.Context) []coord.Leaseholder {
	return f.holders
}

func TestCoordinationDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp coordinationResponse
	if code := getJSON(t, srv, "/admin/api/coordination", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Error("expected disabled when no coordination inspector wired")
	}
	if resp.Leaseholders == nil {
		t.Error("expected non-nil (empty) leaseholders for JSON stability")
	}
}

func TestCoordinationEnabled(t *testing.T) {
	fc := &fakeCoordination{
		enabled: true,
		snap: coord.Snapshot{
			Enabled: true,
			Mode:    "s3",
			NodeID:  "pod-a",
			Jobs: []coord.JobStatus{
				{Job: "backup", IsLeader: true, FencingToken: 7, Acquisitions: 1, Renewals: 5},
				{Job: "cve-drift-rescan", IsLeader: false},
			},
		},
		holders: []coord.Leaseholder{
			{Job: "backup", Held: true, Holder: "pod-a", FencingToken: 7, Self: true},
			{Job: "cve-drift-rescan", Held: true, Holder: "pod-b", FencingToken: 3},
		},
	}
	srv := newTestServer(t, Options{Coordination: fc})
	var resp coordinationResponse
	if code := getJSON(t, srv, "/admin/api/coordination", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || resp.Mode != "s3" || resp.NodeID != "pod-a" {
		t.Fatalf("unexpected header: %+v", resp.Snapshot)
	}
	if len(resp.Jobs) != 2 || !resp.Jobs[0].IsLeader || resp.Jobs[0].FencingToken != 7 {
		t.Fatalf("unexpected jobs: %+v", resp.Jobs)
	}
	if len(resp.Leaseholders) != 2 || resp.Leaseholders[1].Holder != "pod-b" {
		t.Fatalf("unexpected leaseholders: %+v", resp.Leaseholders)
	}
}
