package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
)

// What the console's Mirroring view reads (Task 193), as each kind of reader
// is given it.

// detailedFullMirror is a mirror whose status carries everything a tenant
// must not be shown: the operator's name and reason, the cursor, the recent
// errors' words, the state directory.
type detailedFullMirror struct{ stubFullMirror }

func (s *detailedFullMirror) Status() fullmirror.Status {
	return fullmirror.Status{
		Enabled: true, Leader: true, StateDir: "/var/lib/pt/fullmirror", Tenant: "mirror-tenant",
		Paused: true, PausedBy: "alice@example.com", PauseReason: "registry incident INC-42",
		Upstreams: []fullmirror.UpstreamStatus{s.upstream()},
	}
}

func (s *detailedFullMirror) upstream() fullmirror.UpstreamStatus {
	lag := int64(12)
	return fullmirror.UpstreamStatus{
		Upstream: "npm", Type: "npm", Tier: "a", State: fullmirror.StateBackingOff, Detail: "fetching @acme/internal-tool failed: 502",
		Phase: "follow", Cursor: `{"format":"npm/1","since":"4711"}`, FeedHead: "4723", Lag: &lag,
		PausedBy: "bob@example.com", PauseReason: "bill review",
		Policy:       fullmirror.Policy{Versions: "all", Include: []string{"@acme/.*"}},
		Counters:     fullmirror.Counters{Fetched: 9, Failed: 1},
		RecentErrors: []fullmirror.ErrorRecord{{Time: time.Unix(1700000000, 0), Package: "@acme/internal-tool", Message: "upstream answered 502"}},
	}
}

func (s *detailedFullMirror) UpstreamStatus(name string) (fullmirror.UpstreamStatus, error) {
	if name != "npm" {
		return fullmirror.UpstreamStatus{}, fullmirror.ErrUnknownUpstream
	}
	return s.upstream(), nil
}

func TestFullMirrorStatusIsRedactedForATenant(t *testing.T) {
	h := newFullMirrorServer(t, &detailedFullMirror{}, nil, &recordingAudit{})
	secret := []string{"alice@", "INC-42", "bob@", "bill review", "/var/lib", "mirror-tenant", "4711", "4723", "@acme", "502"}

	// An operator reads everything.
	w := fmDo(h, http.MethodGet, "/admin/api/fullmirror/status", fmViewer, "")
	for _, s := range secret {
		if !strings.Contains(w.Body.String(), s) {
			t.Errorf("a viewer's status lacks %q", s)
		}
	}
	// A tenant-bound identity reads the state and the figures only.
	for _, path := range []string{"/admin/api/fullmirror/status", "/admin/api/fullmirror/status?upstream=npm"} {
		w := fmDo(h, http.MethodGet, path, fmTenant, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
		for _, s := range secret {
			if strings.Contains(w.Body.String(), s) {
				t.Errorf("%s: a tenant is shown %q: %s", path, s, w.Body)
			}
		}
		body := compactJSON(w.Body.Bytes())
		for _, want := range []string{`"state":"backing-off"`, `"lag":12`, `"fetched":9`, `"tier":"a"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the tenant's status lacks %s: %s", path, want, body)
			}
		}
	}
}

// scopedFullScan is a full scan with two tenants' verdicts and figures.
type scopedFullScan struct{ stubFullScan }

func (s *scopedFullScan) Status() fullscan.Status {
	at := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	return fullscan.Status{
		Enabled: true, Subject: fullscan.Subject,
		Tenants: map[string]fullscan.Figures{"team-a": {Cached: 4, Scanned: 3, Malicious: 1}, "team-b": {Cached: 7, Malicious: 2}},
		Upstreams: []fullscan.UpstreamStatus{{
			Upstream: "npm", Figures: fullscan.Figures{Cached: 11, Scanned: 8, Malicious: 3},
			RecentMalicious: []fullscan.Flagged{
				{Path: "/evil-b/-/evil-b-1.0.0.tgz", Ecosystem: "npm", Name: "evil-b", Version: "1.0.0", Scanned: at, Tenants: []string{"team-b"}},
				{Path: "/evil-a/-/evil-a-1.0.0.tgz", Ecosystem: "npm", Name: "evil-a", Version: "1.0.0", Scanned: at.Add(-time.Hour), Tenants: []string{"team-b", "team-a"}},
			},
		}},
	}
}

func (s *scopedFullScan) UpstreamStatus(name string) (fullscan.UpstreamStatus, error) {
	return s.Status().Upstreams[0], nil
}

func TestFullScanStatusIsScopedToTheTenant(t *testing.T) {
	h := newFullScanServer(t, &scopedFullScan{})
	// An organization-wide reader: every verdict, who pulled it, every
	// tenant's figures.
	var st fullscan.Status
	w := fmDo(h, http.MethodGet, "/admin/api/fullscan/status", fmViewer, "")
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &st) != nil {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	if len(st.Upstreams[0].RecentMalicious) != 2 || len(st.Tenants) != 2 || len(st.Upstreams[0].RecentMalicious[1].Tenants) != 2 {
		t.Fatalf("a viewer's status %+v", st)
	}
	// team-a: its own figures, and the verdict on the package it pulled —
	// not team-b's package, not that team-b pulled the other one too.
	w = fmDo(h, http.MethodGet, "/admin/api/fullscan/status", fmTenant, "")
	st = fullscan.Status{}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &st) != nil {
		t.Fatalf("tenant status: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "team-b") || strings.Contains(w.Body.String(), "evil-b") {
		t.Fatalf("team-a is shown team-b's data: %s", w.Body)
	}
	ups := st.Upstreams[0]
	if len(ups.RecentMalicious) != 1 || ups.RecentMalicious[0].Name != "evil-a" || st.Tenants["team-a"].Malicious != 1 {
		t.Fatalf("team-a's status %+v / %+v", ups.RecentMalicious, st.Tenants)
	}
	// One upstream, the same way.
	w = fmDo(h, http.MethodGet, "/admin/api/fullscan/status?upstream=npm", fmTenant, "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "evil-b") || !strings.Contains(w.Body.String(), "evil-a") {
		t.Fatalf("team-a's upstream status: %d %s", w.Code, w.Body)
	}
}
