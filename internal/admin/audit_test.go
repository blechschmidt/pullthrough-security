package admin

import (
	"context"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

// newAuditLogger builds a transparency-enabled audit logger seeded with n events.
func newAuditLogger(t *testing.T, n int) *audit.Logger {
	t.Helper()
	l, err := audit.NewLogger(context.Background(), audit.Options{
		Key:          []byte("admin-audit-test-key"),
		Sink:         audit.NewMemorySink(),
		Transparency: &audit.TransparencyOptions{SealEvery: -1},
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := l.Log(context.Background(), audit.Event{Type: audit.EventPolicy, Subject: "alice", Decision: audit.DecisionDeny}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	return l
}

func TestAuditStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp auditStatusResponse
	if code := getJSON(t, srv, "/admin/api/audit", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Enabled {
		t.Fatal("expected disabled when no audit logger is wired")
	}
}

func TestAuditStatusReportsStats(t *testing.T) {
	l := newAuditLogger(t, 6)
	if _, _, err := l.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	srv := newTestServer(t, Options{Audit: l})

	var resp auditStatusResponse
	if code := getJSON(t, srv, "/admin/api/audit", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !resp.Enabled || !resp.TransparencyEnabled || resp.Stats == nil {
		t.Fatalf("expected enabled transparency status, got %+v", resp)
	}
	if resp.Stats.ChainLength != 6 || resp.Stats.TreeSize != 6 {
		t.Fatalf("unexpected stats: %+v", resp.Stats)
	}
	if resp.LatestCheckpoint == nil || resp.LatestCheckpoint.TreeSize != 6 {
		t.Fatalf("expected latest checkpoint of size 6, got %+v", resp.LatestCheckpoint)
	}
}

func TestAuditCheckpointEndpoint(t *testing.T) {
	l := newAuditLogger(t, 4)
	if _, _, err := l.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	srv := newTestServer(t, Options{Audit: l})

	var cp audit.Checkpoint
	if code := getJSON(t, srv, "/admin/api/audit/checkpoint", "", &cp); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if cp.TreeSize != 4 || cp.RootHash == "" {
		t.Fatalf("unexpected checkpoint: %+v", cp)
	}
}

func TestAuditInclusionProofEndpoint(t *testing.T) {
	l := newAuditLogger(t, 8)
	if _, _, err := l.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	srv := newTestServer(t, Options{Audit: l})

	var proof audit.InclusionProof
	if code := getJSON(t, srv, "/admin/api/audit/proof?seq=3", "", &proof); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	// The proof returned by the admin API must verify independently.
	if err := audit.VerifyInclusion(proof); err != nil {
		t.Fatalf("returned inclusion proof does not verify: %v", err)
	}
	if proof.LeafIndex != 2 {
		t.Fatalf("leaf index = %d, want 2 (seq 3)", proof.LeafIndex)
	}

	// Missing/invalid seq is a 400.
	if code := getJSON(t, srv, "/admin/api/audit/proof", "", nil); code != http.StatusBadRequest {
		t.Fatalf("missing seq status = %d, want 400", code)
	}
	// Out-of-range seq is a 404.
	if code := getJSON(t, srv, "/admin/api/audit/proof?seq=999", "", nil); code != http.StatusNotFound {
		t.Fatalf("out-of-range seq status = %d, want 404", code)
	}
}

func TestAuditConsistencyProofEndpoint(t *testing.T) {
	l := newAuditLogger(t, 10)
	srv := newTestServer(t, Options{Audit: l})

	var proof audit.ConsistencyProof
	if code := getJSON(t, srv, "/admin/api/audit/consistency?from=4&to=10", "", &proof); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if err := audit.VerifyConsistency(proof); err != nil {
		t.Fatalf("returned consistency proof does not verify: %v", err)
	}

	// Invalid range is a 400.
	if code := getJSON(t, srv, "/admin/api/audit/consistency?from=20&to=10", "", nil); code != http.StatusBadRequest {
		t.Fatalf("invalid range status = %d, want 400", code)
	}
}

func TestAuditEndpointsTransparencyDisabled(t *testing.T) {
	// A logger without the transparency layer: chain works, proofs do not.
	l, err := audit.NewLogger(context.Background(), audit.Options{
		Key:  []byte("k"),
		Sink: audit.NewMemorySink(),
	})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	_ = l.Log(context.Background(), audit.Event{Type: audit.EventPull})
	srv := newTestServer(t, Options{Audit: l})

	if code := getJSON(t, srv, "/admin/api/audit/checkpoint", "", nil); code != http.StatusNotFound {
		t.Fatalf("checkpoint status = %d, want 404 when transparency is off", code)
	}
	if code := getJSON(t, srv, "/admin/api/audit/proof?seq=1", "", nil); code != http.StatusNotFound {
		t.Fatalf("proof status = %d, want 404 when transparency is off", code)
	}
	// Status still reports the chain length.
	var resp auditStatusResponse
	if code := getJSON(t, srv, "/admin/api/audit", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !resp.Enabled || resp.TransparencyEnabled || resp.Stats.ChainLength != 1 {
		t.Fatalf("unexpected status with transparency off: %+v", resp)
	}
}
