package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/clientip"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The download-log tests drive the gateway with the two real protocol adapters
// the task names — the cargo sparse registry and the Go module proxy — in front
// of a stub registry, so what is asserted is what the log records for the
// requests those package managers really send.

const (
	crateBody  = "CRATE-BYTES-cfg-if-1.0.0"
	moduleBody = "MODULE-ZIP-BYTES-rsc.io/quote-v1.5.2"
)

// registryStub serves a tiny crates.io and a tiny GOPROXY, and counts requests.
type registryStub struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
	// hold, when non-nil, makes artifact requests wait until it is closed or the
	// request is canceled.
	hold chan struct{}
}

func newRegistryStub(t *testing.T) *registryStub {
	t.Helper()
	s := &registryStub{hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		hold := s.hold
		s.mu.Unlock()
		switch r.URL.Path {
		case "/config.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"dl":"https://static.crates.io/crates","api":"https://crates.io"}`)
		case "/cf/g-/cfg-if":
			_, _ = io.WriteString(w, `{"name":"cfg-if","vers":"1.0.0","deps":[],"cksum":"00","features":{},"yanked":false}`+"\n")
		case "/api/v1/crates/cfg-if/1.0.0/download", "/api/v1/crates/itoa/1.0.11/download":
			if hold != nil {
				select {
				case <-hold:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("ETag", `"crate-etag"`)
			_, _ = io.WriteString(w, crateBody)
		case "/api/v1/crates/broken/1.0.0/download":
			http.Error(w, "upstream exploded", http.StatusInternalServerError)
		case "/rsc.io/quote/@v/list":
			_, _ = io.WriteString(w, "v1.5.2\n")
		case "/rsc.io/quote/@v/v1.5.2.info":
			_, _ = io.WriteString(w, `{"Version":"v1.5.2","Time":"2018-02-14T15:44:20Z"}`)
		case "/rsc.io/quote/@v/v1.5.2.mod":
			_, _ = io.WriteString(w, "module rsc.io/quote\n")
		case "/rsc.io/quote/@v/v1.5.2.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = io.WriteString(w, moduleBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *registryStub) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

// logGateway is a gateway fronting the stub with the real cargo and go
// backends and a download log.
type logGateway struct {
	*Gateway
	handler http.Handler
	log     *downloadlog.Log
	stub    *registryStub
}

type logGatewayOptions struct {
	deps    func(*Dependencies)
	opts    func(*Options)
	logCfg  downloadlog.Config
	withLog *bool // nil/true: wire a log; false: leave Dependencies.DownloadLog nil
}

func newLogGateway(t *testing.T, o logGatewayOptions) *logGateway {
	t.Helper()
	stub := newRegistryStub(t)
	client := upstream.NewWithHTTPClient(http.DefaultClient, "test/1")

	registry := backends.NewRegistry()
	cargo, err := pkgmgr.NewCargo(pkgmgr.Options{
		Name: "cargo", UpstreamURL: stub.URL, Client: client,
		PublicBaseURL: "http://proxy.test/v1/cargo",
		// The stub plays the download host as well as the index.
		Settings: map[string]string{"downloadUrl": stub.URL},
	})
	if err != nil {
		t.Fatalf("NewCargo: %v", err)
	}
	goproxy, err := pkgmgr.NewGoProxy(pkgmgr.Options{
		Name: "go", UpstreamURL: stub.URL, Client: client,
		Settings: map[string]string{"sumdb": "off"},
	})
	if err != nil {
		t.Fatalf("NewGoProxy: %v", err)
	}
	for _, b := range []backends.Backend{cargo, goproxy} {
		if err := registry.Register(b); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	var log *downloadlog.Log
	if o.withLog == nil || *o.withLog {
		cfg := o.logCfg
		cfg.Enabled = true
		log, err = downloadlog.New(cfg)
		if err != nil {
			t.Fatalf("downloadlog.New: %v", err)
		}
	}

	deps := Dependencies{
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:       cache.NewMemoryCache(),
		Backends:    registry,
		Ecosystems:  map[string]string{"cargo": "cargo", "go": "go"},
		DownloadLog: log,
	}
	if o.deps != nil {
		o.deps(&deps)
	}
	opts := Options{HTTPAddr: ":0"}
	if o.opts != nil {
		o.opts(&opts)
	}
	g, err := New(deps, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &logGateway{Gateway: g, handler: g.Handler(), log: log, stub: stub}
}

// do sends a request from the given client address and returns the response.
func (g *logGateway) do(t *testing.T, method, path, remoteAddr string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Add(header[i], header[i+1])
	}
	rr := httptest.NewRecorder()
	g.handler.ServeHTTP(rr, req)
	return rr
}

// entries returns the log, newest first.
func (g *logGateway) entries(t *testing.T) []downloadlog.Entry {
	t.Helper()
	res, err := g.log.Query(downloadlog.Query{Limit: -1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	return res.Entries
}

// only returns the single entry of the log.
func (g *logGateway) only(t *testing.T) downloadlog.Entry {
	t.Helper()
	entries := g.entries(t)
	if len(entries) != 1 {
		t.Fatalf("the log holds %d entries, want exactly 1: %+v", len(entries), entries)
	}
	return entries[0]
}

const (
	cratePath  = "/v1/cargo/api/v1/crates/cfg-if/1.0.0/download"
	modulePath = "/v1/go/rsc.io/quote/@v/v1.5.2.zip"
)

// A crate download is recorded with the address it came from and the crate's
// coordinate — the first time from upstream, the second time from the cache,
// each attributed to its own client.
func TestDownloadLogRecordsCargoDownloads(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})

	rr := g.do(t, http.MethodGet, cratePath, "10.1.1.5:40001", "User-Agent", "cargo/1.84.0 (9fc6b4312 2025-01-08)")
	if rr.Code != http.StatusOK || rr.Body.String() != crateBody {
		t.Fatalf("first download: status %d body %q", rr.Code, rr.Body.String())
	}
	first := g.only(t)
	want := downloadlog.Entry{
		ID: 1, Time: first.Time, DurationMs: first.DurationMs,
		ClientIP: "10.1.1.5", Ecosystem: "cargo", Upstream: "cargo",
		Package: "cfg-if", Version: "1.0.0", Artifact: "cfg-if-1.0.0.crate", Kind: downloadlog.KindPackage,
		Method: http.MethodGet, Path: cratePath, Status: http.StatusOK, Outcome: downloadlog.OutcomeServed,
		Cache: "MISS", Bytes: int64(len(crateBody)), Size: int64(len(crateBody)),
		UserAgent: "cargo/1.84.0 (9fc6b4312 2025-01-08)",
	}
	if first != want {
		t.Fatalf("first entry\n %+v\nwant\n %+v", first, want)
	}
	if first.Time.IsZero() {
		t.Fatal("the entry has no time")
	}

	// A second machine pulls the same crate: served from the cache, logged
	// against the second address.
	rr = g.do(t, http.MethodGet, cratePath, "10.1.1.6:40002")
	if rr.Code != http.StatusOK {
		t.Fatalf("second download: status %d", rr.Code)
	}
	entries := g.entries(t)
	if len(entries) != 2 {
		t.Fatalf("%d entries, want 2", len(entries))
	}
	second := entries[0]
	if second.ClientIP != "10.1.1.6" || second.Cache != "HIT" || second.Package != "cfg-if" || second.Outcome != downloadlog.OutcomeServed {
		t.Fatalf("second entry = %+v", second)
	}
	if got := g.stub.count("/api/v1/crates/cfg-if/1.0.0/download"); got != 1 {
		t.Fatalf("the crate was fetched from upstream %d times, want once", got)
	}

	// "Who pulled cfg-if?" — both addresses, and only them.
	sum, err := g.log.Summarize(downloadlog.Query{Package: "cfg-if"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Clients != 2 || sum.ByClient[0].ClientIP != "10.1.1.6" || sum.ByClient[1].ClientIP != "10.1.1.5" {
		t.Fatalf("clients of cfg-if = %+v", sum.ByClient)
	}
}

// The requests cargo makes before the download — config.json, the index file —
// are metadata: they say what a client looked up, not what it installed.
func TestDownloadLogSkipsCargoMetadataByDefault(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	for _, path := range []string{"/v1/cargo/config.json", "/v1/cargo/cf/g-/cfg-if"} {
		if rr := g.do(t, http.MethodGet, path, "10.1.1.5:1"); rr.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, rr.Code)
		}
	}
	if got := g.entries(t); len(got) != 0 {
		t.Fatalf("metadata requests were logged: %+v", got)
	}
}

// What `go mod download` sends for one module: list, .info, .mod, .zip. Only
// the zip is the module.
func TestDownloadLogRecordsGoModuleDownloads(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	const client = "192.168.7.20:53000"
	for _, path := range []string{
		"/v1/go/rsc.io/quote/@v/list",
		"/v1/go/rsc.io/quote/@v/v1.5.2.info",
		"/v1/go/rsc.io/quote/@v/v1.5.2.mod",
		modulePath,
	} {
		if rr := g.do(t, http.MethodGet, path, client, "User-Agent", "Go-http-client/1.1"); rr.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, rr.Code)
		}
	}
	e := g.only(t)
	if e.ClientIP != "192.168.7.20" || e.Ecosystem != "go" || e.Upstream != "go" ||
		e.Package != "rsc.io/quote" || e.Version != "v1.5.2" || e.Artifact != "v1.5.2.zip" ||
		e.Kind != downloadlog.KindPackage || e.Outcome != downloadlog.OutcomeServed ||
		e.Path != modulePath || e.Bytes != int64(len(moduleBody)) || e.Cache != "MISS" || e.UserAgent != "Go-http-client/1.1" {
		t.Fatalf("module entry = %+v", e)
	}
}

// With includeMetadata the lookups are recorded too, marked as metadata, so the
// packages-only view is still one filter away.
func TestDownloadLogIncludeMetadata(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{logCfg: downloadlog.Config{IncludeMetadata: true}})
	const client = "192.168.7.20:53000"
	for _, path := range []string{
		"/v1/go/rsc.io/quote/@v/list",
		"/v1/go/rsc.io/quote/@v/v1.5.2.info",
		modulePath,
	} {
		g.do(t, http.MethodGet, path, client)
	}
	entries := g.entries(t)
	if len(entries) != 3 {
		t.Fatalf("%d entries, want 3", len(entries))
	}
	kinds := map[string]downloadlog.Kind{}
	for _, e := range entries {
		kinds[e.Path] = e.Kind
	}
	if kinds["/v1/go/rsc.io/quote/@v/list"] != downloadlog.KindMetadata ||
		kinds["/v1/go/rsc.io/quote/@v/v1.5.2.info"] != downloadlog.KindMetadata ||
		kinds[modulePath] != downloadlog.KindPackage {
		t.Fatalf("kinds = %v", kinds)
	}
	res, err := g.log.Query(downloadlog.Query{Kind: downloadlog.KindPackage})
	if err != nil || res.Total != 1 {
		t.Fatalf("packages-only view: %d entries, %v", res.Total, err)
	}
}

// A refused download is the entry an incident responder looks for first: it is
// recorded with the gate that refused it and the gate's explanation, and it
// never reaches the upstream.
func TestDownloadLogRecordsBlockedAttempts(t *testing.T) {
	feed := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{
			ID: "MAL-2026-0001", Ecosystem: "cargo", Name: "itoa", AllVersions: true,
			Summary: "credential stealer", Source: "test",
		}},
		InitialLoaded: true,
	})
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) { d.Malfeed = feed }})

	rr := g.do(t, http.MethodGet, "/v1/cargo/api/v1/crates/itoa/1.0.11/download", "10.9.8.7:1234")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rr.Code)
	}
	e := g.only(t)
	if e.Outcome != downloadlog.OutcomeBlocked || e.Gate != "malfeed" || e.Status != http.StatusForbidden {
		t.Fatalf("outcome/gate/status = %s/%s/%d, want blocked/malfeed/403", e.Outcome, e.Gate, e.Status)
	}
	// The refusal's body is an explanation, not package content: no bytes of
	// the crate went out.
	if e.Bytes != 0 || rr.Body.Len() == 0 {
		t.Fatalf("blocked entry records %d bytes sent (response body: %d bytes); want 0", e.Bytes, rr.Body.Len())
	}
	if e.ClientIP != "10.9.8.7" || e.Package != "itoa" || e.Version != "1.0.11" || e.Ecosystem != "cargo" {
		t.Fatalf("blocked entry = %+v", e)
	}
	// The code and reason are the gate's own, as sent to the client.
	var body struct{ Code, Reason string }
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Code == "" || body.Reason == "" {
		t.Fatalf("refusal body %q: %v", rr.Body.String(), err)
	}
	if e.Code != body.Code || e.Reason != body.Reason {
		t.Fatalf("entry code/reason = %q/%q, want the gate's %q/%q", e.Code, e.Reason, body.Code, body.Reason)
	}
	if got := g.stub.count("/api/v1/crates/itoa/1.0.11/download"); got != 0 {
		t.Fatalf("a blocked crate was fetched from upstream %d times", got)
	}

	// The good crate next to it is served and logged as served: one blocked
	// entry does not taint the others.
	g.do(t, http.MethodGet, cratePath, "10.9.8.7:1235")
	res, err := g.log.Query(downloadlog.Query{Outcome: downloadlog.OutcomeBlocked})
	if err != nil || res.Total != 1 || res.Entries[0].Package != "itoa" {
		t.Fatalf("blocked view = %+v, %v", res, err)
	}
	if st := g.log.Stats(); st.ByOutcome[downloadlog.OutcomeBlocked] != 1 || st.ByOutcome[downloadlog.OutcomeServed] != 1 {
		t.Fatalf("stats = %v", st.ByOutcome)
	}
}

// The go command asks for a version's .info and .mod before its .zip, and a
// gate that judges a coordinate refuses the first of them. The client stops
// there — so that refused metadata request is the whole trace of the attempt,
// and it is recorded although metadata requests otherwise are not.
func TestDownloadLogRecordsModuleBlockedAtItsMetadata(t *testing.T) {
	feed := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{ID: "MAL-2", Ecosystem: "go", Name: "rsc.io/quote", AllVersions: true, Source: "test"}},
		InitialLoaded:  true,
	})
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) { d.Malfeed = feed }})

	// The version list names no version, so no gate judges it; it is metadata
	// and is served without a trace in the log.
	if rr := g.do(t, http.MethodGet, "/v1/go/rsc.io/quote/@v/list", "10.3.3.3:1"); rr.Code != http.StatusOK {
		t.Fatalf("list: status %d", rr.Code)
	}
	if got := g.entries(t); len(got) != 0 {
		t.Fatalf("the version list was logged: %+v", got)
	}

	if rr := g.do(t, http.MethodGet, "/v1/go/rsc.io/quote/@v/v1.5.2.info", "10.3.3.3:2"); rr.Code != http.StatusForbidden {
		t.Fatalf(".info: status %d, want 403", rr.Code)
	}
	e := g.only(t)
	if e.Kind != downloadlog.KindMetadata || e.Outcome != downloadlog.OutcomeBlocked || e.Gate != "malfeed" {
		t.Fatalf("kind/outcome/gate = %s/%s/%s, want metadata/blocked/malfeed", e.Kind, e.Outcome, e.Gate)
	}
	if e.ClientIP != "10.3.3.3" || e.Package != "rsc.io/quote" || e.Version != "v1.5.2" || e.Artifact != "v1.5.2.info" {
		t.Fatalf("entry = %+v", e)
	}
	// "Who tried to pull the blocked module?" finds it.
	res, err := g.log.Query(downloadlog.Query{Package: "rsc.io/quote", Outcome: downloadlog.OutcomeBlocked})
	if err != nil || res.Total != 1 {
		t.Fatalf("blocked view: %d entries, %v", res.Total, err)
	}
}

// A HEAD transfers nothing and is not a download — unless it is refused: a
// client told "blocked" on its probe never sends the GET.
func TestDownloadLogHeadRequests(t *testing.T) {
	feed := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{ID: "MAL-1", Ecosystem: "cargo", Name: "itoa", AllVersions: true, Source: "test"}},
		InitialLoaded:  true,
	})
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) { d.Malfeed = feed }})

	if rr := g.do(t, http.MethodHead, cratePath, "10.1.1.5:1"); rr.Code != http.StatusOK {
		t.Fatalf("HEAD status %d", rr.Code)
	}
	if got := g.entries(t); len(got) != 0 {
		t.Fatalf("a served HEAD was logged as a download: %+v", got)
	}

	if rr := g.do(t, http.MethodHead, "/v1/cargo/api/v1/crates/itoa/1.0.11/download", "10.1.1.5:2"); rr.Code != http.StatusForbidden {
		t.Fatalf("blocked HEAD status %d", rr.Code)
	}
	e := g.only(t)
	if e.Method != http.MethodHead || e.Outcome != downloadlog.OutcomeBlocked || e.Gate != "malfeed" || e.Package != "itoa" {
		t.Fatalf("blocked HEAD entry = %+v", e)
	}
}

func TestDownloadLogOutcomes(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})

	// Not found upstream.
	if rr := g.do(t, http.MethodGet, "/v1/cargo/api/v1/crates/nope/9.9.9/download", "10.0.0.1:1"); rr.Code != http.StatusNotFound {
		t.Fatalf("missing crate: status %d", rr.Code)
	}
	e := g.entries(t)[0]
	if e.Outcome != downloadlog.OutcomeNotFound || e.Status != 404 || e.Package != "nope" || e.Version != "9.9.9" || e.Size != 0 || e.Bytes != 0 {
		t.Fatalf("not-found entry = %+v", e)
	}

	// Upstream failure.
	if rr := g.do(t, http.MethodGet, "/v1/cargo/api/v1/crates/broken/1.0.0/download", "10.0.0.1:2"); rr.Code < 500 {
		t.Fatalf("broken crate: status %d", rr.Code)
	}
	e = g.entries(t)[0]
	if e.Outcome != downloadlog.OutcomeError || e.Package != "broken" || e.Gate != "" || e.Bytes != 0 {
		t.Fatalf("error entry = %+v", e)
	}

	// A byte range: served, with fewer bytes than the artifact has.
	g.do(t, http.MethodGet, cratePath, "10.0.0.1:3")
	rr := g.do(t, http.MethodGet, cratePath, "10.0.0.1:4", "Range", "bytes=0-4")
	if rr.Code != http.StatusPartialContent || rr.Body.Len() != 5 {
		t.Fatalf("range request: status %d, %d bytes", rr.Code, rr.Body.Len())
	}
	e = g.entries(t)[0]
	if e.Outcome != downloadlog.OutcomeServed || e.Status != 206 || e.Bytes != 5 || e.Size != int64(len(crateBody)) {
		t.Fatalf("range entry = %+v", e)
	}

	// A revalidation: the client already holds the artifact.
	rr = g.do(t, http.MethodGet, cratePath, "10.0.0.1:5", "If-None-Match", `"crate-etag"`)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("revalidation: status %d", rr.Code)
	}
	e = g.entries(t)[0]
	if e.Outcome != downloadlog.OutcomeNotModified || e.Bytes != 0 || e.Status != 304 {
		t.Fatalf("revalidation entry = %+v", e)
	}
}

// A request that names no resource of a backend is not a download.
func TestDownloadLogIgnoresUnresolvedRequests(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/unknown-backend/whatever"},
		{http.MethodGet, "/v1/cargo/api/v1/crates/a/../b/download"},
		{http.MethodPost, cratePath},
		{http.MethodDelete, cratePath},
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/v1/"},
	} {
		g.do(t, tc.method, tc.path, "10.0.0.1:1")
	}
	if got := g.entries(t); len(got) != 0 {
		t.Fatalf("unresolved requests were logged: %+v", got)
	}
}

// The client address comes from X-Forwarded-For only when the peer is a trusted
// proxy; from anyone else the header is ignored, so a client cannot attribute
// its downloads to another machine.
func TestDownloadLogClientAddressBehindProxies(t *testing.T) {
	resolver, err := clientip.New([]string{"10.255.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	g := newLogGateway(t, logGatewayOptions{opts: func(o *Options) { o.ClientIP = resolver }})

	// Through the trusted load balancer: the forwarded client is logged, and the
	// balancer is named as the forwarder.
	g.do(t, http.MethodGet, cratePath, "10.255.0.10:443", "X-Forwarded-For", "203.0.113.50")
	e := g.entries(t)[0]
	if e.ClientIP != "203.0.113.50" || e.ForwardedBy != "10.255.0.10" {
		t.Fatalf("via trusted proxy: clientIp %q forwardedBy %q, want 203.0.113.50 / 10.255.0.10", e.ClientIP, e.ForwardedBy)
	}

	// A client prepends a forged address; the balancer appends the real one.
	g.do(t, http.MethodGet, cratePath, "10.255.0.10:443", "X-Forwarded-For", "10.1.1.1, 203.0.113.51")
	if e := g.entries(t)[0]; e.ClientIP != "203.0.113.51" {
		t.Fatalf("forged prefix: clientIp %q, want the entry the proxy appended (203.0.113.51)", e.ClientIP)
	}

	// Directly connected, with a forged header: the TCP peer is logged.
	g.do(t, http.MethodGet, cratePath, "198.51.100.77:5555", "X-Forwarded-For", "10.1.1.1")
	e = g.entries(t)[0]
	if e.ClientIP != "198.51.100.77" || e.ForwardedBy != "" {
		t.Fatalf("direct with forged header: clientIp %q forwardedBy %q, want the peer and no forwarder", e.ClientIP, e.ForwardedBy)
	}

	// Without any trusted proxy configured the header is never read.
	plain := newLogGateway(t, logGatewayOptions{})
	plain.do(t, http.MethodGet, cratePath, "10.255.0.10:443", "X-Forwarded-For", "203.0.113.50")
	if e := plain.only(t); e.ClientIP != "10.255.0.10" || e.ForwardedBy != "" {
		t.Fatalf("no trusted proxies: clientIp %q forwardedBy %q", e.ClientIP, e.ForwardedBy)
	}

	// IPv6 clients are logged in canonical form.
	plain.do(t, http.MethodGet, cratePath, "[2001:DB8:0:0:0:0:0:1]:9000")
	if e := plain.entries(t)[0]; e.ClientIP != "2001:db8::1" {
		t.Fatalf("IPv6 clientIp = %q, want 2001:db8::1", e.ClientIP)
	}
}

// With client authentication on, an entry names the authenticated identity; the
// audit trail's pull record names the package, and both agree on the address.
func TestDownloadLogRecordsIdentityAndEnrichesAudit(t *testing.T) {
	az, err := auth.NewAuthorizer([]auth.Role{{Name: "reader", Ecosystems: []string{"cargo", "go"}, Upstreams: []string{"*"}}})
	if err != nil {
		t.Fatal(err)
	}
	ta, err := auth.NewTokenAuthenticator([]auth.TokenEntry{{Name: "ci-runner", Team: "team-a", Roles: []string{"reader"}, Secret: testToken}})
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := auth.NewEnforcer(auth.EnforcerOptions{Authenticator: ta, Authorizer: az, Quota: auth.NewQuotaManager(auth.QuotaOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	sink := audit.NewMemorySink()
	auditLog, err := audit.NewLogger(context.Background(), audit.Options{Key: []byte("k"), Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := clientip.New([]string{"10.255.0.10"})
	if err != nil {
		t.Fatal(err)
	}
	g := newLogGateway(t, logGatewayOptions{
		deps: func(d *Dependencies) { d.Enforcer, d.Audit = enforcer, auditLog },
		opts: func(o *Options) { o.ClientIP = resolver },
	})

	// Unauthenticated: refused before anything is resolved — an authentication
	// event for the audit log, not a download.
	if rr := g.do(t, http.MethodGet, cratePath, "10.255.0.10:1", "X-Forwarded-For", "203.0.113.9"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: status %d", rr.Code)
	}
	if got := g.entries(t); len(got) != 0 {
		t.Fatalf("an unauthenticated request was logged as a download: %+v", got)
	}

	rr := g.do(t, http.MethodGet, cratePath, "10.255.0.10:2",
		"X-Forwarded-For", "203.0.113.9", "Authorization", "Bearer "+testToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("authenticated: status %d", rr.Code)
	}
	e := g.only(t)
	if e.Subject != "ci-runner" || e.Tenant != "team-a" || e.AuthMethod != "token" {
		t.Fatalf("identity = %q/%q/%q, want ci-runner/team-a/token", e.Subject, e.Tenant, e.AuthMethod)
	}
	if e.ClientIP != "203.0.113.9" {
		t.Fatalf("clientIp = %q", e.ClientIP)
	}

	var pull *audit.Event
	var denied *audit.Event
	for _, rec := range sink.Records() {
		ev := rec.Event
		switch ev.Type {
		case audit.EventPull:
			pull = &ev
		case audit.EventAuth:
			denied = &ev
		}
	}
	if pull == nil {
		t.Fatal("no pull record in the audit log")
	}
	if pull.Detail["package"] != "cfg-if" || pull.Detail["version"] != "1.0.0" {
		t.Fatalf("audit pull detail = %v, want the package coordinate", pull.Detail)
	}
	// One definition of "the client": the audit log and the download log agree.
	if pull.RemoteAddr != "203.0.113.9" {
		t.Fatalf("audit pull remoteAddr = %q, want the forwarded client 203.0.113.9", pull.RemoteAddr)
	}
	if denied == nil || denied.RemoteAddr != "203.0.113.9" {
		t.Fatalf("audit auth-denial record = %+v, want it attributed to the forwarded client", denied)
	}
}

// Without client authentication there is no identity to record; the entry does
// not pretend otherwise.
func TestDownloadLogOmitsPlaceholderIdentity(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	g.do(t, http.MethodGet, cratePath, "10.0.0.1:1")
	if e := g.only(t); e.Subject != "" || e.Tenant != "" || e.AuthMethod != "" {
		t.Fatalf("identity fields set without authentication: %q/%q/%q", e.Subject, e.Tenant, e.AuthMethod)
	}
}

// A synthetic pre-warm fetch is the proxy talking to itself, not a client.
func TestDownloadLogIgnoresPrewarmFetches(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	rr := httptest.NewRecorder()
	g.PrewarmHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, cratePath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("prewarm fetch: status %d", rr.Code)
	}
	if got := g.entries(t); len(got) != 0 {
		t.Fatalf("a pre-warm fetch was logged as a download: %+v", got)
	}
	// The artifact it warmed is then served to a real client from the cache.
	g.do(t, http.MethodGet, cratePath, "10.0.0.1:1")
	if e := g.only(t); e.Cache != "HIT" || e.ClientIP != "10.0.0.1" {
		t.Fatalf("entry after pre-warm = %+v", e)
	}
}

// A client that goes away before the proxy answers received nothing; the
// attempt is recorded as a failure, not as a served download.
func TestDownloadLogClientAbort(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	g.stub.mu.Lock()
	g.stub.hold = make(chan struct{})
	g.stub.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, cratePath, nil).WithContext(ctx)
	req.RemoteAddr = "10.0.0.1:1"
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handler.ServeHTTP(httptest.NewRecorder(), req)
	}()
	// Cancel once the upstream fetch is in flight.
	for g.stub.count("/api/v1/crates/cfg-if/1.0.0/download") == 0 {
		select {
		case <-done:
			t.Fatal("the request finished before it could be canceled")
		default:
		}
	}
	cancel()
	<-done

	e := g.only(t)
	if e.Outcome != downloadlog.OutcomeError || e.Status != statusClientClosedRequest || e.Bytes != 0 || e.Package != "cfg-if" {
		t.Fatalf("aborted entry = %+v", e)
	}
}

// The log is optional: a gateway without one, or with a disabled one, serves
// exactly as before.
func TestDownloadLogDisabled(t *testing.T) {
	off := false
	without := newLogGateway(t, logGatewayOptions{withLog: &off})
	if rr := without.do(t, http.MethodGet, cratePath, "10.0.0.1:1"); rr.Code != http.StatusOK {
		t.Fatalf("without a log: status %d", rr.Code)
	}

	disabled, err := downloadlog.New(downloadlog.Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	g := newLogGateway(t, logGatewayOptions{withLog: &off, deps: func(d *Dependencies) { d.DownloadLog = disabled }})
	if rr := g.do(t, http.MethodGet, cratePath, "10.0.0.1:1"); rr.Code != http.StatusOK {
		t.Fatalf("with a disabled log: status %d", rr.Code)
	}
	if st := disabled.Stats(); st.Recorded != 0 {
		t.Fatalf("a disabled log recorded %d entries", st.Recorded)
	}
}

// Many clients at once: every download is recorded exactly once, against the
// right address (run with -race).
func TestDownloadLogConcurrentClients(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	const clients = 40
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := cratePath
			if i%2 == 1 {
				path = modulePath
			}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "10.20.0." + itoa(i+1) + ":1000"
			rr := httptest.NewRecorder()
			g.handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				failures.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d downloads failed", n)
	}
	entries := g.entries(t)
	if len(entries) != clients {
		t.Fatalf("%d entries, want %d", len(entries), clients)
	}
	seen := map[string]string{}
	for _, e := range entries {
		if prev, dup := seen[e.ClientIP]; dup {
			t.Fatalf("address %s logged twice (%s and %s)", e.ClientIP, prev, e.Package)
		}
		seen[e.ClientIP] = e.Package
	}
	for i := 0; i < clients; i++ {
		want := "cfg-if"
		if i%2 == 1 {
			want = "rsc.io/quote"
		}
		if got := seen["10.20.0."+itoa(i+1)]; got != want {
			t.Fatalf("10.20.0.%d pulled %q, want %q", i+1, got, want)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// The explanation of a refusal is read from the gate's JSON body; anything else
// yields nothing rather than garbage.
func TestBlockExplanation(t *testing.T) {
	code, reason := blockExplanation([]byte(`{"error":"x","code":"malicious","reason":"flagged by the scanner","package":"itoa"}`))
	if code != "malicious" || reason != "flagged by the scanner" {
		t.Fatalf("got %q / %q", code, reason)
	}
	for _, body := range []string{"", "plain text refusal", `{"code":`, `[1,2,3]`, strings.Repeat("x", 100)} {
		if code, reason := blockExplanation([]byte(body)); code != "" || reason != "" {
			t.Errorf("blockExplanation(%q) = %q / %q, want nothing", body, code, reason)
		}
	}
}

// A Git LFS error document calls its explanation "message".
func TestBlockExplanationReadsAnLFSError(t *testing.T) {
	code, reason := blockExplanation([]byte(`{"message":"lfs object rejected by content policy"}`))
	if code != "" || reason != "lfs object rejected by content policy" {
		t.Fatalf("got %q / %q", code, reason)
	}
	// A gate's own reason wins over a message next to it.
	if _, reason := blockExplanation([]byte(`{"reason":"the reason","message":"a message"}`)); reason != "the reason" {
		t.Fatalf("reason = %q", reason)
	}
}

// A client that gives up while a gate is still deciding was not refused. The
// package scan answers "do not serve" when its request is cancelled under it —
// there is no one left to serve — and that must not be recorded as the scan's
// verdict on a package it never finished looking at.
func TestDownloadLogClientLeavingDuringAGateIsNotARefusal(t *testing.T) {
	log, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// The model takes far longer than the client is willing to wait.
	fx := newLLMGateFixture(t, llmBenignTarball(), &pkgscantest.Provider{Delay: 30 * time.Second}, nil, func(d *Dependencies) {
		d.DownloadLog = log
	})
	handler := fx.g.Handler()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, llmBenignPath, nil).WithContext(ctx)
	req.RemoteAddr = "10.9.9.9:1234"
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}()
	// Let the artifact be fetched and the scan start, then hang up — what a
	// package manager's own timeout does.
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt32(fx.hits) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the artifact was never fetched")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the handler did not return after its client left")
	}

	res, err := log.Query(downloadlog.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("the log holds %d entries, want 1: %+v", len(res.Entries), res.Entries)
	}
	e := res.Entries[0]
	if e.Outcome != downloadlog.OutcomeError || e.Status != statusClientClosedRequest || e.Gate != "" || e.Bytes != 0 {
		t.Fatalf("a client that hung up during the scan of a benign package is logged as outcome=%s gate=%q status=%d bytes=%d; want error, no gate, %d, 0",
			e.Outcome, e.Gate, e.Status, e.Bytes, statusClientClosedRequest)
	}
}

// lfsLikeBackend stands in for the Git backend's LFS object endpoint. It owns
// the raw request (HTTPHandler), describes it to the download log
// (DownloadDescriber) and puts the object before its gates before it writes a
// byte — the proxy's package scan (Gateway.GateLFSObject, the serve gate wired
// in cmd/pullthrough) and a content gate of its own, whose refusal it reports
// through the request context — as internal/git does.
type lfsLikeBackend struct {
	gateway       **Gateway
	content       []byte
	oid           string
	ownGateBlocks bool
}

func (b *lfsLikeBackend) Name() string { return "gitlfs" }
func (b *lfsLikeBackend) Resolve(context.Context, *backends.Request) (*backends.Resolved, error) {
	return nil, backends.ErrNotSupported
}
func (b *lfsLikeBackend) Fetch(context.Context, *backends.Resolved) (*backends.FetchResult, error) {
	return nil, backends.ErrNotSupported
}
func (b *lfsLikeBackend) DescribeDownload(r *http.Request, _ string) (backends.Download, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return backends.Download{}, false
	}
	return backends.Download{Name: "org/repo.git", Artifact: b.oid, Digest: "sha256:" + b.oid}, true
}
func (b *lfsLikeBackend) ServeBackendHTTP(w http.ResponseWriter, r *http.Request, _ string) {
	g := *b.gateway
	key := "sha256:" + b.oid
	if _, err := g.deps.Cache.Put(r.Context(), key, bytes.NewReader(b.content), map[string]string{}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if b.ownGateBlocks {
		backends.RecordRefusal(r.Context(), "lfs-content")
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"lfs object rejected by content policy"}`)
		return
	}
	if !g.GateLFSObject(w, r, "gitlfs", "org/repo.git", b.oid, int64(len(b.content)), key) {
		return // the gate wrote the refusal
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b.content)
	}
}

// A Git LFS object a gate refuses is a blocked download like any other — also
// when the request is a HEAD, and whichever of the two gates on the object
// refused it. Neither gate passes the core's gate bookkeeping: the Git backend
// calls the package scan directly and runs the content gate itself.
func TestDownloadLogRecordsRefusedLFSObjects(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ownGateBlocks bool
		gate, reason  string
	}{
		{"refused by the package scan", false, "llmpkgscan", ""},
		{"refused by the backend's content gate", true, "lfs-content", "lfs object rejected by content policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log, err := downloadlog.New(downloadlog.Config{Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			content := llmEvilTarball()
			sum := sha256.Sum256(content)
			var gw *Gateway
			be := &lfsLikeBackend{gateway: &gw, content: content, oid: hex.EncodeToString(sum[:]), ownGateBlocks: tc.ownGateBlocks}
			fx := newLLMGateFixture(t, content, &pkgscantest.Provider{}, nil, func(d *Dependencies) {
				d.DownloadLog = log
				if err := d.Backends.Register(be); err != nil {
					t.Fatal(err)
				}
			})
			gw = fx.g
			handler := fx.g.Handler()

			for _, method := range []string{http.MethodGet, http.MethodHead} {
				req := httptest.NewRequest(method, "/v1/gitlfs/org/repo.git/info/lfs/objects/"+be.oid, nil)
				req.RemoteAddr = "10.7.7.7:1"
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				if rr.Code != http.StatusForbidden {
					t.Fatalf("%s: status %d, want the gate's 403", method, rr.Code)
				}
			}
			res, err := log.Query(downloadlog.Query{})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Entries) != 2 {
				t.Fatalf("%d entries for a refused GET and a refused HEAD, want 2: %+v", len(res.Entries), res.Entries)
			}
			for _, e := range res.Entries {
				if e.Outcome != downloadlog.OutcomeBlocked || e.Gate != tc.gate || e.Status != http.StatusForbidden {
					t.Errorf("%s: outcome=%s gate=%q status=%d, want blocked by %s with 403", e.Method, e.Outcome, e.Gate, e.Status, tc.gate)
				}
				if e.Package != "org/repo.git" || e.Artifact != be.oid || e.ClientIP != "10.7.7.7" || e.Bytes != 0 {
					t.Errorf("%s: entry = %+v", e.Method, e)
				}
				if tc.reason != "" && e.Method == http.MethodGet && e.Reason != tc.reason {
					t.Errorf("reason = %q, want %q", e.Reason, tc.reason)
				}
			}
		})
	}
}

// silentBackend answers a described download with nothing at all.
type silentBackend struct{}

func (silentBackend) Name() string { return "silent" }
func (silentBackend) Resolve(context.Context, *backends.Request) (*backends.Resolved, error) {
	return nil, backends.ErrNotSupported
}
func (silentBackend) Fetch(context.Context, *backends.Resolved) (*backends.FetchResult, error) {
	return nil, backends.ErrNotSupported
}
func (silentBackend) DescribeDownload(*http.Request, string) (backends.Download, bool) {
	return backends.Download{Name: "org/repo.git"}, true
}
func (silentBackend) ServeBackendHTTP(http.ResponseWriter, *http.Request, string) {}

// A handler that returns without answering leaves the server to send an empty
// "200 OK" on its behalf. To a client that is still there that is an empty
// file, not a download — and the log must not call it "served", nor claim the
// client had left.
func TestDownloadLogDoesNotCallAnEmptyAnswerADownload(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) {
		if err := d.Backends.Register(silentBackend{}); err != nil {
			t.Fatal(err)
		}
	}})
	rr := g.do(t, http.MethodPost, "/v1/silent/org/repo.git/git-upload-pack", "10.0.0.1:1")
	if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
		t.Fatalf("the scenario needs an unanswered request: status %d, %d bytes", rr.Code, rr.Body.Len())
	}
	e := g.only(t)
	if e.Outcome != downloadlog.OutcomeError || e.Status != http.StatusOK || e.Bytes != 0 || e.Reason == "" {
		t.Fatalf("an unanswered request is logged as outcome=%s status=%d bytes=%d reason=%q; want an error that says nothing was sent",
			e.Outcome, e.Status, e.Bytes, e.Reason)
	}
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// What an entry holds is cut from the request: the path from the request line,
// the package name from the path. An entry that kept those cuts as they are
// would keep the request line they were cut from alive — and a client decides
// how long that is. Padding the query string of an ordinary, cached download
// must not make its log entry cost what the request did.
//
// The requests go through a real HTTP server, so that what reaches the log is
// what net/http really hands a handler.
func TestDownloadLogEntryDoesNotKeepTheRequestAlive(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	srv := httptest.NewServer(g.handler)
	defer srv.Close()
	client := srv.Client()
	get := func(url string) {
		t.Helper()
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}

	const requests = 120
	const padBytes = 512 << 10
	url := srv.URL + cratePath
	get(url) // warm the cache: what follows are hits, with no upstream cost
	pad := strings.Repeat("A", padBytes)
	before := heapInUse()
	for i := 0; i < requests; i++ {
		get(url + "?pad=" + pad)
	}
	pad = ""
	retained := int64(heapInUse()) - int64(before)

	entries := g.entries(t)
	if len(entries) != requests+1 {
		t.Fatalf("%d entries, want %d", len(entries), requests+1)
	}
	for _, e := range entries {
		if strings.Contains(e.Path, "pad=") || len(e.Path) > 100 {
			t.Fatalf("the query string reached the log: path %q", e.Path)
		}
	}
	// 120 requests carried 60 MiB of padding. Their entries are a few hundred
	// bytes each; anything near the padding means they pin the request lines.
	if limit := int64(requests * padBytes / 8); retained > limit {
		t.Errorf("%d padded requests left %.1f MiB on the heap (%.0f KiB per entry): the entries keep their request lines alive",
			requests, float64(retained)/(1<<20), float64(retained)/requests/1024)
	}
	runtime.KeepAlive(g)
}
