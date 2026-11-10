package malfeed

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDoer is a programmable HTTP transport for the refresh tests. It serves a
// fixed body with an ETag and replies 304 when the conditional header matches.
type fakeDoer struct {
	body     string
	etag     string
	calls    atomic.Int32
	notMod   atomic.Int32
	failNext atomic.Bool
}

func (d *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls.Add(1)
	if d.failNext.Load() {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("boom")),
			Header:     http.Header{},
		}, nil
	}
	if inm := req.Header.Get("If-None-Match"); inm != "" && inm == d.etag {
		d.notMod.Add(1)
		return &http.Response{
			StatusCode: http.StatusNotModified,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     http.Header{},
		}, nil
	}
	h := http.Header{}
	h.Set("ETag", d.etag)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Header:     h,
	}, nil
}

func TestService_CheckBlocksMatch(t *testing.T) {
	entries, _ := ParseOSVStream([]byte(fixtureFeed), "fixture")
	svc := NewService(Config{InitialEntries: entries, InitialLoaded: true})
	defer svc.Close()

	d := svc.Check(Coordinate{Ecosystem: "npm", Name: "evil-stealer", Version: "1.0.0"})
	if !d.Blocked || d.Code != "malicious" {
		t.Fatalf("expected malicious block, got %+v", d)
	}
	if d.AdvisoryID() != "MAL-2024-0001" {
		t.Fatalf("expected advisory id, got %q", d.AdvisoryID())
	}

	clean := svc.Check(Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if clean.Blocked {
		t.Fatalf("clean coordinate must not block: %+v", clean)
	}

	snap := svc.Metrics()
	if snap.Blocks != 1 || snap.Checks != 2 {
		t.Fatalf("unexpected metrics: %+v", snap)
	}
	if snap.BlocksByEcosystem["npm"] != 1 {
		t.Fatalf("expected per-ecosystem block count, got %+v", snap.BlocksByEcosystem)
	}
}

func TestService_StalenessFailOpenVsClosed(t *testing.T) {
	entries, _ := ParseOSVStream([]byte(fixtureFeed), "fixture")

	// Fail-open (default): a stale feed still blocks matches but serves the rest.
	open := NewService(Config{InitialEntries: entries, StaleAfter: time.Hour})
	defer open.Close()
	// lastRefresh is zero (InitialLoaded not set) → stale.
	if !open.Stale() {
		t.Fatal("expected fresh-never-loaded feed to be stale")
	}
	if d := open.Check(Coordinate{Ecosystem: "npm", Name: "clean-pkg"}); d.Blocked {
		t.Fatalf("fail-open must not block a clean pull when stale: %+v", d)
	}
	if d := open.Check(Coordinate{Ecosystem: "npm", Name: "evil-stealer", Version: "1.0.0"}); !d.Blocked {
		t.Fatal("fail-open must still block a concrete match when stale")
	}

	// Fail-closed: a stale feed blocks everything.
	closed := NewService(Config{InitialEntries: entries, StaleAfter: time.Hour, FailClosedWhenStale: true})
	defer closed.Close()
	d := closed.Check(Coordinate{Ecosystem: "npm", Name: "clean-pkg"})
	if !d.Blocked || d.Code != "feed-stale" {
		t.Fatalf("fail-closed must block a clean pull when stale: %+v", d)
	}
	if closed.Metrics().StaleBlocks != 1 {
		t.Fatalf("expected a stale-block to be counted: %+v", closed.Metrics())
	}
}

func TestService_StaleAfterDisabled(t *testing.T) {
	// StaleAfter == 0 disables freshness checks entirely.
	svc := NewService(Config{StaleAfter: 0})
	defer svc.Close()
	if svc.Stale() {
		t.Fatal("StaleAfter=0 must never report stale")
	}
}

func TestService_ConditionalRefresh(t *testing.T) {
	doer := &fakeDoer{body: fixtureFeed, etag: `"v1"`}
	svc := NewService(Config{
		Sources:    []FeedSource{{URL: "https://feed.test/malicious.json", Name: "test"}},
		HTTPClient: doer,
		StaleAfter: time.Hour,
	})
	defer svc.Close()

	ctx := context.Background()
	if err := svc.Refresh(ctx); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if svc.Matcher().Len() != 4 {
		t.Fatalf("expected 4 entries after refresh, got %d", svc.Matcher().Len())
	}
	if svc.Stale() {
		t.Fatal("feed should be fresh after a successful refresh")
	}

	// Second refresh sends If-None-Match and gets a 304 → entries retained.
	if err := svc.Refresh(ctx); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if doer.notMod.Load() != 1 {
		t.Fatalf("expected one 304 response, got %d", doer.notMod.Load())
	}
	if svc.Matcher().Len() != 4 {
		t.Fatalf("entries must survive a 304, got %d", svc.Matcher().Len())
	}
	if svc.Metrics().Refreshes != 2 {
		t.Fatalf("expected 2 refreshes, got %d", svc.Metrics().Refreshes)
	}
}

func TestService_RefreshFailureRetainsEntries(t *testing.T) {
	doer := &fakeDoer{body: fixtureFeed, etag: `"v1"`}
	svc := NewService(Config{
		Sources:    []FeedSource{{URL: "https://feed.test/m.json", Name: "test"}},
		HTTPClient: doer,
	})
	defer svc.Close()

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	doer.failNext.Store(true)
	err := svc.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected an error when the only source fails")
	}
	// The previously-loaded entries must be retained on a total failure.
	if svc.Matcher().Len() != 4 {
		t.Fatalf("entries must survive a failed refresh, got %d", svc.Matcher().Len())
	}
	if svc.Metrics().RefreshFailures != 1 {
		t.Fatalf("expected a refresh failure to be counted: %+v", svc.Metrics())
	}
}

func TestService_NilSafe(t *testing.T) {
	var svc *Service
	if d := svc.Check(Coordinate{Ecosystem: "npm", Name: "x"}); d.Blocked {
		t.Fatal("nil service must allow everything")
	}
	if svc.Stale() {
		t.Fatal("nil service must not be stale")
	}
	if svc.Enabled() {
		t.Fatal("nil service must report disabled")
	}
	_ = svc.Close()
}
