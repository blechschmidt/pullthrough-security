package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// A refusal the LLM package-content scan gate defers to the system caller
// (the full mirror's fetch under the full scan) is a refusal in the download
// log: blocked by llmpkgscan, with the gate's code and the caller it was
// deferred to — not "served", which would say the proxy let a flagged package
// through while the mirror counts it refused and the full scan evicts it
// (found by the full-mirror end-to-end suite, Task 194). A benign object the
// same caller fetches is served as before.
func TestDeferredLLMRefusalIsLoggedAsBlocked(t *testing.T) {
	dl, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	fx := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{}, nil, func(d *Dependencies) { d.DownloadLog = dl })
	res, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "npm", Path: evilBackendPath, Tenant: "team-a", Subject: "system:full-mirror", UserAgent: "pullthrough-full-mirror",
		DeferLLMRefusal: true, DeferredTo: "full-scan", NoReview: true,
	}, nil)
	if err != nil || !res.Admitted || res.LLMScan == nil || !res.LLMScan.Deferred {
		t.Fatalf("deferred fetch: %+v %v", res, err)
	}
	q, err := dl.Query(downloadlog.Query{Limit: -1})
	if err != nil || len(q.Entries) != 1 {
		t.Fatalf("download log: %v %+v", err, q.Entries)
	}
	e := q.Entries[0]
	if e.Via != downloadlog.ViaSystem || e.Outcome != downloadlog.OutcomeBlocked || e.Status != http.StatusForbidden ||
		e.Gate != "llmpkgscan" || e.Code == "" || e.Bytes != 0 || !strings.Contains(e.Reason, "deferred to full-scan") {
		t.Fatalf("the deferred refusal is logged as %+v", e)
	}

	// The same caller's fetch of a benign object is served.
	fx.payload.Store(llmBenignTarball())
	res, err = fx.g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "npm", Path: strings.TrimPrefix(llmBenignPath, "/v1/npm"), Tenant: "team-a", Subject: "system:full-mirror",
		DeferLLMRefusal: true, DeferredTo: "full-scan", NoReview: true,
	}, nil)
	if err != nil || !res.Admitted || (res.LLMScan != nil && res.LLMScan.Deferred) {
		t.Fatalf("benign fetch: %+v %v", res, err)
	}
	q, err = dl.Query(downloadlog.Query{Limit: -1})
	if err != nil || len(q.Entries) != 2 {
		t.Fatalf("download log: %v %+v", err, q.Entries)
	}
	if e := q.Entries[0]; e.Outcome != downloadlog.OutcomeServed || e.Gate != "" || e.Status != http.StatusOK {
		t.Fatalf("the benign fetch is logged as %+v", e)
	}
}

// A deferred refusal is logged as one only when the caller's ladder enforces
// it — a verdict, and no break-glass grant that releases the bytes. Under an
// approved grant the full scan releases the object (a client's pull is served),
// and under failMode closed a provider outage is a passing fault the full scan
// retries rather than enforces: both system fetches are logged as served, as
// the mirror counts them.
func TestDeferredLLMRefusalNotLoggedWhenReleased(t *testing.T) {
	ap, err := approvals.New(approvals.Config{Enabled: true, RequiredApprovers: 1, GrantTTL: time.Hour},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	dl, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	fx := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{}, nil, func(d *Dependencies) { d.Approvals = ap; d.DownloadLog = dl })
	if rr := fx.pull(llmEvilPath); rr.Code != http.StatusForbidden {
		t.Fatalf("a client's pull: %d", rr.Code)
	}
	pending := ap.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending reviews: %+v", pending)
	}
	if _, err := ap.Approve(context.Background(), pending[0].ID, approvals.ApproveInput{Approver: "ops", Justification: "false positive"}); err != nil {
		t.Fatal(err)
	}
	res, err := fx.g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "npm", Path: evilBackendPath, Subject: "system:full-mirror", DeferLLMRefusal: true, DeferredTo: "full-scan", NoReview: true,
	}, nil)
	if err != nil || res.LLMScan == nil || res.LLMScan.BreakGlass == "" {
		t.Fatalf("the fetch under the grant: %+v %v", res, err)
	}
	q, err := dl.Query(downloadlog.Query{Via: downloadlog.ViaSystem, Limit: -1})
	if err != nil || len(q.Entries) != 1 || q.Entries[0].Outcome != downloadlog.OutcomeServed || q.Entries[0].Gate != "" {
		t.Fatalf("the fetch under the grant is logged as %+v (%v)", q.Entries, err)
	}

	dl2, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	down := newLLMGateFixture(t, llmEvilTarball(), &pkgscantest.Provider{Err: io.ErrUnexpectedEOF},
		func(c *llmpkgscan.Config) { c.FailMode = llmpkgscan.FailClosed; c.MaxRetries = -1 },
		func(d *Dependencies) { d.DownloadLog = dl2 })
	res, err = down.g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "npm", Path: evilBackendPath, Subject: "system:full-mirror", DeferLLMRefusal: true, DeferredTo: "full-scan", NoReview: true,
	}, nil)
	if err != nil || res.LLMScan == nil || !res.LLMScan.Deferred || res.LLMScan.Report.Scanned() {
		t.Fatalf("the fetch with the provider down: %+v %v", res, err)
	}
	q, err = dl2.Query(downloadlog.Query{Limit: -1})
	if err != nil || len(q.Entries) != 1 || q.Entries[0].Outcome != downloadlog.OutcomeServed {
		t.Fatalf("the fetch with the provider down is logged as %+v (%v)", q.Entries, err)
	}
}
