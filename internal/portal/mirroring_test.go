package portal

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
)

type fakeFullMirror struct{ st fullmirror.Status }

func (f fakeFullMirror) Status() fullmirror.Status { return f.st }

type fakeFullScan struct{ st fullscan.Status }

func (f fakeFullScan) Status() fullscan.Status { return f.st }

// The overview's mirroring tile (Task 193): how many registries are mirrored
// whole, and the full scan's figures of the artifacts the caller's own tenant
// pulled — never another tenant's, never what names an artifact.
func TestSummaryMirroringTileIsTenantScoped(t *testing.T) {
	srv := seededServer(t)
	if rec := do(t, srv, "/api/portal/summary", tokAlice); strings.Contains(rec.Body.String(), `"mirroring": {`) {
		t.Fatalf("a tile without a full mirror or scan: %s", rec.Body)
	}

	srv.opts.FullMirror = fakeFullMirror{st: fullmirror.Status{Enabled: true, PausedBy: "alice-the-operator", Upstreams: []fullmirror.UpstreamStatus{
		{Upstream: "npm", Phase: "follow", BootstrapFinished: time.Unix(1_700_000_000, 0), Cursor: "cursor-secret"},
		{Upstream: "cargo", Phase: "bootstrap"},
	}}}
	srv.opts.FullScan = fakeFullScan{st: fullscan.Status{
		Enabled: true, Paused: true, PausedBy: "op", Budget: fullscan.BudgetStatus{Exhausted: true},
		Totals: fullscan.Figures{Cached: 999, Malicious: 50},
		Tenants: map[string]fullscan.Figures{
			"acme":   {Cached: 10, Scanned: 7, NotApplicable: 2, Pending: 1, Malicious: 1, Quarantined: 1},
			"globex": {Cached: 77, Scanned: 70, Malicious: 9},
		},
		Upstreams: []fullscan.UpstreamStatus{{Upstream: "npm", RecentMalicious: []fullscan.Flagged{{Path: "/globex-secret/-/x.tgz", Tenants: []string{"globex"}}}}},
	}}

	var got struct {
		Mirroring *mirroringTally `json:"mirroring"`
		Sources   map[string]bool `json:"sources"`
	}
	srv.mirroringAt = time.Time{} // the statuses are read again
	rec := do(t, srv, "/api/portal/summary", tokAlice)
	decode(t, rec, &got)
	m := got.Mirroring
	if m == nil || m.Mirror == nil || m.Scan == nil || !got.Sources["mirroring"] {
		t.Fatalf("summary %s", rec.Body)
	}
	if *m.Mirror != (mirrorTally{Upstreams: 2, Enumerated: 1}) {
		t.Errorf("mirror %+v", *m.Mirror)
	}
	want := scanTally{Cached: 10, Scanned: 7, NotApplicable: 2, Pending: 1, Malicious: 1, Quarantined: 1, Paused: true, BudgetExhausted: true}
	if *m.Scan != want {
		t.Errorf("acme's scan %+v, want %+v", *m.Scan, want)
	}
	for _, leak := range []string{"globex", "77", "999", "cursor-secret", "alice-the-operator", "/globex-secret"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("acme's summary shows %q: %s", leak, rec.Body)
		}
	}

	// bob's tenant pulled other things; a tenant with no pulls sees zeros.
	got.Mirroring = nil
	decode(t, do(t, srv, "/api/portal/summary", tokBob), &got)
	if got.Mirroring.Scan.Cached != 77 || got.Mirroring.Scan.Malicious != 9 {
		t.Errorf("globex's scan %+v", *got.Mirroring.Scan)
	}
	// The statuses are reused for a while, however many requests come.
	srv.opts.FullScan = fakeFullScan{st: fullscan.Status{Enabled: true}}
	got.Mirroring = nil
	decode(t, do(t, srv, "/api/portal/summary", tokAlice), &got)
	if got.Mirroring.Scan == nil || got.Mirroring.Scan.Cached != 10 {
		t.Errorf("the statuses were read again at once: %+v", got.Mirroring.Scan)
	}
	srv.mirroringAt = time.Now().Add(-mirroringTTL)
	got.Mirroring = nil
	decode(t, do(t, srv, "/api/portal/summary", tokAlice), &got)
	if got.Mirroring.Scan == nil || *got.Mirroring.Scan != (scanTally{}) {
		t.Errorf("a tenant with no pulls: %+v", got.Mirroring.Scan)
	}
}

// The tile renders the summary's figures as text (Task 193): the function
// that builds it uses no HTML sink, and the overview adds it only when the
// summary carries a mirroring block.
func TestMirroringTileRendersText(t *testing.T) {
	b, err := fs.ReadFile(portalFS, "app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	start := strings.Index(js, "function mirroringStat(m)")
	if start < 0 {
		t.Fatal("app.js has no mirroringStat")
	}
	end := strings.Index(js[start:], "\n  }\n")
	body := js[start : start+end]
	if m := regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\bhtml:`).FindString(body); m != "" {
		t.Fatalf("mirroringStat uses an HTML sink: %s", m)
	}
	if !strings.Contains(js, "if (data.mirroring) cards.appendChild(mirroringStat(data.mirroring));") {
		t.Error("the overview does not add the tile")
	}
}
