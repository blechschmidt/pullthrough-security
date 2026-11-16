package proxy

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

const crateDownload = "/api/v1/crates/cfg-if/1.0.0/download"

// SystemLookup (Task 189) predicts the key a system fetch fills and tells
// whether the cache holds it, without fetching anything.
func TestSystemLookupPredictsTheCacheKey(t *testing.T) {
	for _, namespaced := range []bool{false, true} {
		g := newLogGateway(t, logGatewayOptions{opts: func(o *Options) { o.CacheNamespacing = namespaced }})
		ctx := context.Background()
		req := SystemFetchRequest{Backend: "cargo", Path: crateDownload, Tenant: "team-a", Subject: "system:full-mirror"}
		lk, err := g.SystemLookup(ctx, req)
		if err != nil || !lk.Cacheable || lk.Cached {
			t.Fatalf("namespaced=%v: before the fetch: %+v %v", namespaced, lk, err)
		}
		if g.stub.count(crateDownload) != 0 {
			t.Fatal("a lookup reached the upstream")
		}
		res, err := g.SystemFetch(ctx, req, nil)
		if err != nil || !res.Admitted {
			t.Fatalf("fetch %+v %v", res, err)
		}
		lk, err = g.SystemLookup(ctx, req)
		if err != nil || !lk.Cached || lk.CacheKey != res.CacheKey || lk.Size != int64(len(crateBody)) {
			t.Fatalf("namespaced=%v: after the fetch: %+v (fetch filled %q) %v", namespaced, lk, res.CacheKey, err)
		}
		if namespaced && !strings.HasPrefix(lk.CacheKey, "team-a/") {
			t.Errorf("namespaced key %q", lk.CacheKey)
		}
		if len(g.entries(t)) != 1 {
			t.Errorf("a lookup was logged as a download")
		}
	}

	g := newLogGateway(t, logGatewayOptions{})
	ctx := context.Background()
	// An index document is not cached: the lookup says so, and a fetch
	// agrees.
	lk, err := g.SystemLookup(ctx, SystemFetchRequest{Backend: "cargo", Path: "/cf/g-/cfg-if"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := g.SystemFetch(ctx, SystemFetchRequest{Backend: "cargo", Path: "/cf/g-/cfg-if"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lk.Cacheable != res.Admitted {
		t.Errorf("lookup cacheable=%v but the fetch admitted=%v (cache %s)", lk.Cacheable, res.Admitted, res.Cache)
	}
	for _, bad := range []SystemFetchRequest{
		{Backend: "nope", Path: "/x"}, {Backend: "cargo", Path: "x"}, {Backend: "cargo", Path: "/x?y"},
		{Backend: "cargo", Path: "/a/../b"}, {Backend: "cargo", Path: "/a/%2e%2e/b"}, {Backend: "", Path: "/x"},
	} {
		if _, err := g.SystemLookup(ctx, bad); err == nil {
			t.Errorf("lookup %+v accepted", bad)
		}
	}
}

// A system fetch's size limit refuses a larger object before anything is
// cached — whether the upstream states the size or not — and leaves nothing
// behind that a client would trip over.
func TestSystemFetchSizeLimit(t *testing.T) {
	coal := coalesce.New[*cache.Entry](coalesce.Config{Enabled: true}, classifyUpstreamError)
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) { d.Coalescer = coal }})
	ctx := context.Background()

	for _, path := range []string{crateDownload, "/api/v1/crates/streamed/1.0.0/download"} {
		req := SystemFetchRequest{Backend: "cargo", Path: path, Tenant: "team-a", MaxBytes: 10, Subject: "system:full-mirror"}
		res, err := g.SystemFetch(ctx, req, nil)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if res.Status != http.StatusRequestEntityTooLarge || res.Code != CodeTooLarge || res.Admitted || res.Gate != "" {
			t.Fatalf("%s: over the limit: %+v", path, res)
		}
		if lk, err := g.SystemLookup(ctx, req); err != nil || lk.Cached {
			t.Fatalf("%s: an object over the limit was cached: %+v %v", path, lk, err)
		}
		// A client asking right after gets the object: the refusal was the
		// system fetch's alone, and nothing was negatively cached.
		rr := g.do(t, http.MethodGet, "/v1/cargo"+path, "10.0.0.9:1")
		if rr.Code != http.StatusOK || !strings.HasPrefix(rr.Body.String(), crateBody) {
			t.Fatalf("%s: the client after the refusal: %d %q", path, rr.Code, rr.Body.String())
		}
	}
	// A limit the object fits in changes nothing.
	g2 := newLogGateway(t, logGatewayOptions{})
	res, err := g2.SystemFetch(ctx, SystemFetchRequest{Backend: "cargo", Path: crateDownload, MaxBytes: int64(len(crateBody))}, nil)
	if err != nil || !res.Admitted || res.Cache != "MISS" {
		t.Fatalf("within the limit: %+v %v", res, err)
	}
	if _, err := g2.SystemFetch(ctx, SystemFetchRequest{Backend: "cargo", Path: crateDownload, MaxBytes: -1}, nil); err == nil {
		t.Error("a negative limit was accepted")
	}
}

// The upstream's Retry-After on a 429 reaches the client and the system
// fetch; a value that is not one is not relayed.
func TestUpstreamRetryAfterIsRelayed(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	rr := g.do(t, http.MethodGet, "/v1/cargo/api/v1/crates/throttled/1.0.0/download", "10.0.0.2:1")
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "7" {
		t.Fatalf("client: %d Retry-After %q", rr.Code, rr.Header().Get("Retry-After"))
	}
	res, err := g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "cargo", Path: "/api/v1/crates/throttled/1.0.0/download"}, nil)
	if err != nil || res.Status != http.StatusTooManyRequests || res.RetryAfter != 7*time.Second {
		t.Fatalf("system fetch: %+v %v", res, err)
	}
	rr = g.do(t, http.MethodGet, "/v1/cargo/api/v1/crates/garbled/1.0.0/download", "10.0.0.2:1")
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "" {
		t.Fatalf("garbled: %d Retry-After %q", rr.Code, rr.Header().Get("Retry-After"))
	}
	var e downloadlog.Entry
	for _, x := range g.entries(t) {
		if x.Via == downloadlog.ViaSystem {
			e = x
		}
	}
	if e.Subject != "system:release-pinner" || e.UserAgent != "pullthrough-release-pinner" {
		t.Errorf("default subject and user agent: %+v", e)
	}
}

func TestSystemFetchCarriesTheCallersIdentity(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	var body bytes.Buffer
	res, err := g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "cargo", Path: crateDownload, Tenant: "mirror", Subject: "system:full-mirror", UserAgent: "pullthrough-full-mirror",
	}, &body)
	if err != nil || !res.Admitted {
		t.Fatal(res, err)
	}
	e := g.only(t)
	if e.Subject != "system:full-mirror" || e.UserAgent != "pullthrough-full-mirror" || e.Via != downloadlog.ViaSystem || e.Tenant != "mirror" {
		t.Errorf("entry %+v", e)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"":                              0,
		"0":                             0,
		"-5":                            0,
		"120":                           2 * time.Minute,
		"99999999":                      maxRetryAfter,
		"Mon, 16 Nov 2026 12:00:30 GMT": 30 * time.Second,
		"Mon, 16 Nov 2026 11:00:00 GMT": 0,
		"soon":                          0,
	} {
		if got := parseRetryAfter(v, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", v, got, want)
		}
	}
	for v, want := range map[string]string{
		"7": "7", " 7 ": "7", "-1": "", "soon": "", "99999999": "86400",
		// A date is relayed as the seconds until it, bounded to a day.
		"Mon, 16 Nov 2026 12:00:30 GMT": "30",
		"Mon, 16 Nov 2026 11:00:00 GMT": "0",
		"Thu, 31 Dec 2099 00:00:00 GMT": "86400",
	} {
		if got := relayRetryAfterAt(v, now); got != want {
			t.Errorf("relayRetryAfterAt(%q) = %q, want %q", v, got, want)
		}
	}
}

// A path SystemFetch decodes ("%2E" is ".") is decoded by SystemLookup too:
// it predicts the key the fetch filled.
func TestSystemLookupDecodesThePathLikeTheFetch(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	ctx := context.Background()
	res, err := g.SystemFetch(ctx, SystemFetchRequest{Backend: "go", Path: "/rsc.io/quote/@v/v1.5.2.zip"}, nil)
	if err != nil || !res.Admitted {
		t.Fatalf("fetch %+v %v", res, err)
	}
	lk, err := g.SystemLookup(ctx, SystemFetchRequest{Backend: "go", Path: "/rsc.io/quote/@v/v1%2E5%2E2.zip"})
	if err != nil || !lk.Cached || lk.CacheKey != res.CacheKey {
		t.Fatalf("lookup of the encoded spelling: %+v (fetch filled %q) %v", lk, res.CacheKey, err)
	}
}

func TestBlockAction(t *testing.T) {
	for body, want := range map[string]string{
		`{"code":"engine-unavailable","action":"fail-closed"}`: "fail-closed",
		`{"code":"infected","action":"block"}`:                 "block",
		`{"code":"x"}`:                                         "",
		`not json`:                                             "",
		``:                                                     "",
	} {
		if got := blockAction([]byte(body)); got != want {
			t.Errorf("blockAction(%q) = %q, want %q", body, got, want)
		}
	}
}
