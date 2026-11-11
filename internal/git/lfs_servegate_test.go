package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Tests for the Git LFS serve gate: LFSServeGate, Backend.SetLFSServeGate,
// Backend.LFSEnabled and the ServeRefused counter.
//
// The serve gate stands in front of every object request — a cache hit as much
// as a fetch, a Range or HEAD request as much as a whole download. It runs once
// the object is in the cache and before a byte of the response is written, and
// when it refuses, the refusal it wrote is the whole response.

// lfsGateRefusal is the body the test serve gate answers a refused request with.
const lfsGateRefusal = "refused by the serve gate\n"

// lfsGatedBlob returns an n-byte LFS object none of whose bytes is ASCII, so a
// single byte of it in a refusal — which is text — cannot be mistaken for
// anything else. Its first four bytes are 0x80 0x81 0x82 0x83.
func lfsGatedBlob(n int) []byte {
	blob := make([]byte, n)
	for i := range blob {
		blob[i] = 0x80 | byte(i%0x80)
	}
	return blob
}

// lfsGateCall is one consultation of the serve gate.
type lfsGateCall struct {
	info     LFSObjectInfo
	cacheKey string
	method   string
	rng      string // the request's Range header
	cached   []byte // the object as read from the cache under cacheKey, inside the gate
	cacheErr error  // the error of that read
}

// lfsGateSpy is a serve gate that records every consultation and, when it
// refuses, answers the request itself with a 403 — the way a real gate does.
type lfsGateSpy struct {
	// cache, when set, is read under cacheKey on every consultation.
	cache cache.Cache
	// refuse makes the gate refuse every request from now on.
	refuse atomic.Bool
	// refuseIf, when set, picks the requests to refuse. Set it before the gate
	// is installed.
	refuseIf func(*http.Request) bool

	mu    sync.Mutex
	calls []lfsGateCall
}

func (g *lfsGateSpy) gate(w http.ResponseWriter, r *http.Request, info LFSObjectInfo, cacheKey string) bool {
	call := lfsGateCall{info: info, cacheKey: cacheKey, method: r.Method, rng: r.Header.Get("Range")}
	if g.cache != nil {
		entry, err := g.cache.Get(r.Context(), cacheKey)
		if err != nil {
			call.cacheErr = err
		} else {
			call.cached, call.cacheErr = io.ReadAll(entry.Content)
			entry.Content.Close()
		}
	}
	g.mu.Lock()
	g.calls = append(g.calls, call)
	g.mu.Unlock()

	if g.refuse.Load() || (g.refuseIf != nil && g.refuseIf(r)) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Policy-Decision", "block")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, lfsGateRefusal)
		return false
	}
	return true
}

// seen returns a copy of the consultations so far.
func (g *lfsGateSpy) seen() []lfsGateCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]lfsGateCall(nil), g.calls...)
}

func (g *lfsGateSpy) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

// lfsObjectRequest issues one object request through the proxy: any method,
// through any repository path, with any size hint and request headers.
func lfsObjectRequest(b *Backend, method, repo, oid string, sizeHint int64, header http.Header) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	target := "/v1/gh/" + repo + "/info/lfs/objects/" + oid + "?size=" + strconv.FormatInt(sizeHint, 10)
	req := httptest.NewRequest(method, target, nil)
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	b.ServeBackendHTTP(rr, req, repo+"/info/lfs/objects/"+oid)
	return rr
}

// assertNoObjectBytes fails when body holds the object, or so much as one of
// the byte values the object is made of.
func assertNoObjectBytes(t *testing.T, body, blob []byte) {
	t.Helper()
	if len(blob) > 0 && bytes.Contains(body, blob) {
		t.Errorf("the response body contains the whole object (%d bytes)", len(blob))
		return
	}
	var ofObject [256]bool
	for _, b := range blob {
		ofObject[b] = true
	}
	for i, b := range body {
		if ofObject[b] {
			t.Errorf("response body byte %d (%#02x) is a byte of the object; body = %q", i, b, body)
			return
		}
	}
}

// assertLFSGateRefusal checks that the response is the gate's refusal and
// nothing else: its status, its header, its body — and none of the object.
func assertLFSGateRefusal(t *testing.T, rr *httptest.ResponseRecorder, blob []byte) {
	t.Helper()
	res := rr.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want the gate's 403", res.StatusCode)
	}
	if got := res.Header.Get("X-Policy-Decision"); got != "block" {
		t.Errorf("X-Policy-Decision = %q, want the gate's %q", got, "block")
	}
	if got := rr.Body.String(); got != lfsGateRefusal {
		t.Errorf("body = %q, want exactly what the gate wrote, %q", got, lfsGateRefusal)
	}
	assertNoObjectBytes(t, rr.Body.Bytes(), blob)
}

// TestLFSServeGateCalledOnMissAndHit: the gate is consulted when the object is
// fetched and again when it is served from the cache. Each time it is told
// which object, of what size, through which repository of which upstream, and
// the key it is handed is the one the object is cached under — the object can
// already be read back under it from inside the gate.
func TestLFSServeGateCalledOnMissAndHit(t *testing.T) {
	blob := lfsGatedBlob(1024)
	oid := oidOf(blob)
	size := int64(len(blob))
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	c := cache.NewMemoryCache()
	b := newLFSBackend(t, up.srv.URL, c, LFSOptions{})
	spy := &lfsGateSpy{cache: c}
	b.SetLFSServeGate(spy.gate)

	wantKey := "sha256:" + oid
	check := func(t *testing.T, n int, wantRepo string) {
		t.Helper()
		calls := spy.seen()
		if len(calls) != n {
			t.Fatalf("gate consulted %d times, want %d", len(calls), n)
		}
		call := calls[n-1]
		if want := (LFSObjectInfo{OID: oid, Size: size, Repo: wantRepo, Upstream: "gh"}); call.info != want {
			t.Errorf("gate info = %+v, want %+v", call.info, want)
		}
		if call.cacheKey != wantKey {
			t.Errorf("gate cacheKey = %q, want %q", call.cacheKey, wantKey)
		}
		if call.cacheErr != nil || !bytes.Equal(call.cached, blob) {
			t.Errorf("reading the object from the cache under %q inside the gate: %d bytes, err %v; want the %d-byte object",
				call.cacheKey, len(call.cached), call.cacheErr, len(blob))
		}
	}

	// A miss: fetched from upstream, cached, then put before the gate.
	first := doObject(b, oid, size, "")
	if first.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), blob) {
		t.Fatalf("first request = %d with a %d-byte body, want 200 and the object", first.Code, first.Body.Len())
	}
	check(t, 1, "o/r.git")

	// A hit: nothing is fetched, the gate is consulted all the same.
	second := doObject(b, oid, size, "")
	if second.Code != http.StatusOK || !bytes.Equal(second.Body.Bytes(), blob) {
		t.Fatalf("second request = %d with a %d-byte body, want 200 and the object", second.Code, second.Body.Len())
	}
	check(t, 2, "o/r.git")

	// Objects are cached by OID alone, so the same object asked for through
	// another repository is a hit as well. The gate is told the repository this
	// request came through, and the size is the object's, not the client's hint.
	third := lfsObjectRequest(b, http.MethodGet, "other/mirror.git", oid, 1, nil)
	if third.Code != http.StatusOK || !bytes.Equal(third.Body.Bytes(), blob) {
		t.Fatalf("request through another repository = %d with a %d-byte body, want 200 and the object", third.Code, third.Body.Len())
	}
	check(t, 3, "other/mirror.git")

	// The repository path the gate sees is the sanitized one.
	fourth := lfsObjectRequest(b, http.MethodGet, "o//r.git", oid, size, nil)
	if fourth.Code != http.StatusOK {
		t.Fatalf("request through an unclean repository path = %d, want 200", fourth.Code)
	}
	check(t, 4, "o/r.git")

	if got := atomic.LoadInt32(&up.storageHits); got != 1 {
		t.Errorf("upstream storage hits = %d, want 1 (only the first request was a miss)", got)
	}
	m := b.LFSMetrics()
	if m.CacheMisses != 1 || m.CacheHits != 3 {
		t.Errorf("metrics misses=%d hits=%d, want 1/3", m.CacheMisses, m.CacheHits)
	}
	if m.ServeRefused != 0 {
		t.Errorf("ServeRefused = %d, want 0 (the gate allowed every request)", m.ServeRefused)
	}
}

// TestLFSServeGateRefusalIsTheWholeResponse: when the gate returns false the
// client gets what the gate wrote and nothing of the object, the refusal is
// counted, and no object bytes are counted as served — on the request that
// fetched the object and on the next one alike.
func TestLFSServeGateRefusalIsTheWholeResponse(t *testing.T) {
	blob := lfsGatedBlob(1024)
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})
	spy := &lfsGateSpy{}
	spy.refuse.Store(true)
	b.SetLFSServeGate(spy.gate)

	for i := 1; i <= 2; i++ {
		rr := doObject(b, oid, int64(len(blob)), "")
		assertLFSGateRefusal(t, rr, blob)
		if got := rr.Result().Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Errorf("request %d: Content-Type = %q, want the gate's", i, got)
		}

		m := b.LFSMetrics()
		if m.ServeRefused != int64(i) {
			t.Errorf("request %d: ServeRefused = %d, want %d", i, m.ServeRefused, i)
		}
		if m.BytesServed != 0 {
			t.Errorf("request %d: BytesServed = %d, want 0", i, m.BytesServed)
		}
		if m.ObjectRequests != int64(i) {
			t.Errorf("request %d: ObjectRequests = %d, want %d", i, m.ObjectRequests, i)
		}
		if n := spy.count(); n != i {
			t.Errorf("request %d: gate consulted %d times, want %d", i, n, i)
		}
	}

	// The backend leaves a refused object where it is — what becomes of it is
	// the gate's to decide, it has the key — so the second request was a cache
	// hit and the upstream was asked for the object once.
	if got := atomic.LoadInt32(&up.storageHits); got != 1 {
		t.Errorf("upstream storage hits = %d, want 1", got)
	}
	if m := b.LFSMetrics(); m.CacheMisses != 1 || m.CacheHits != 1 {
		t.Errorf("metrics misses=%d hits=%d, want 1/1", m.CacheMisses, m.CacheHits)
	}
}

// lfsRequestShapes are the ways a client asks for an object, with what each
// yields when it is served. The serve gate stands in front of every one.
var lfsRequestShapes = []struct {
	name       string
	method     string
	header     func(oid string) http.Header
	wantStatus int
	wantBody   func(blob []byte) []byte
}{
	{
		name:       "whole object",
		method:     http.MethodGet,
		header:     func(string) http.Header { return nil },
		wantStatus: http.StatusOK,
		wantBody:   func(blob []byte) []byte { return blob },
	},
	{
		name:       "range",
		method:     http.MethodGet,
		header:     func(string) http.Header { return http.Header{"Range": {"bytes=0-3"}} },
		wantStatus: http.StatusPartialContent,
		wantBody:   func(blob []byte) []byte { return blob[:4] },
	},
	{
		name:       "HEAD",
		method:     http.MethodHead,
		header:     func(string) http.Header { return nil },
		wantStatus: http.StatusOK,
		wantBody:   func([]byte) []byte { return nil },
	},
	{
		name:       "conditional",
		method:     http.MethodGet,
		header:     func(oid string) http.Header { return http.Header{"If-None-Match": {`"` + oid + `"`}} },
		wantStatus: http.StatusNotModified,
		wantBody:   func([]byte) []byte { return nil },
	},
}

// TestLFSServeGateEveryRequestShape: a whole download, a Range request, a HEAD
// and a conditional request each consult the gate exactly once — whether the
// object has to be fetched first or is already cached — and always about the
// whole object. A refusal is the entire answer: a ranged read does not slip
// past the gate, and nothing of the object is counted as served. When the gate
// allows, each request yields what it would have without a gate.
func TestLFSServeGateEveryRequestShape(t *testing.T) {
	for _, shape := range lfsRequestShapes {
		for _, cached := range []bool{false, true} {
			for _, refuse := range []bool{true, false} {
				name := shape.name + "/cache miss"
				if cached {
					name = shape.name + "/cache hit"
				}
				if refuse {
					name += "/refused"
				} else {
					name += "/allowed"
				}
				t.Run(name, func(t *testing.T) {
					blob := lfsGatedBlob(1024)
					oid := oidOf(blob)
					size := int64(len(blob))
					up := newLFSUpstream(t, map[string][]byte{oid: blob})
					b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})
					spy := &lfsGateSpy{}
					b.SetLFSServeGate(spy.gate)

					if cached {
						// Warm the cache with a download the gate allows.
						if rr := doObject(b, oid, size, ""); rr.Code != http.StatusOK {
							t.Fatalf("warming the cache: status = %d", rr.Code)
						}
					}
					before, consulted := b.LFSMetrics(), spy.count()
					spy.refuse.Store(refuse)

					rr := lfsObjectRequest(b, shape.method, "o/r.git", oid, size, shape.header(oid))

					// Consulted once for this request, as it was asked, about the object as a whole.
					calls := spy.seen()
					if len(calls) != consulted+1 {
						t.Fatalf("gate consulted %d times for one request, want 1", len(calls)-consulted)
					}
					call := calls[len(calls)-1]
					if call.method != shape.method || call.rng != shape.header(oid).Get("Range") {
						t.Errorf("gate saw a %s request with Range %q, want %s with Range %q",
							call.method, call.rng, shape.method, shape.header(oid).Get("Range"))
					}
					if want := (LFSObjectInfo{OID: oid, Size: size, Repo: "o/r.git", Upstream: "gh"}); call.info != want {
						t.Errorf("gate info = %+v, want %+v", call.info, want)
					}

					after := b.LFSMetrics()
					if refuse {
						assertLFSGateRefusal(t, rr, blob)
						if cr := rr.Result().Header.Values("Content-Range"); len(cr) != 0 {
							t.Errorf("Content-Range = %q on a refusal, want the header absent", cr)
						}
						if got := after.ServeRefused - before.ServeRefused; got != 1 {
							t.Errorf("ServeRefused moved by %d, want 1", got)
						}
						if got := after.BytesServed - before.BytesServed; got != 0 {
							t.Errorf("BytesServed moved by %d for a refused request, want 0", got)
						}
						return
					}

					wantBody := shape.wantBody(blob)
					if rr.Code != shape.wantStatus {
						t.Errorf("status = %d, want %d", rr.Code, shape.wantStatus)
					}
					if !bytes.Equal(rr.Body.Bytes(), wantBody) {
						t.Errorf("body = %d bytes %q, want %d bytes %q", rr.Body.Len(), rr.Body.Bytes(), len(wantBody), wantBody)
					}
					if shape.wantStatus == http.StatusPartialContent {
						if cr, want := rr.Header().Get("Content-Range"), fmt.Sprintf("bytes 0-3/%d", size); cr != want {
							t.Errorf("Content-Range = %q, want %q", cr, want)
						}
					}
					if after.ServeRefused != 0 {
						t.Errorf("ServeRefused = %d, want 0", after.ServeRefused)
					}
					if got := after.BytesServed - before.BytesServed; got != int64(len(wantBody)) {
						t.Errorf("BytesServed moved by %d, want %d", got, len(wantBody))
					}
				})
			}
		}
	}
}

// lfsJournalGate is a content gate that notes its invocation in a journal the
// serve gate of the same test writes to as well.
type lfsJournalGate struct {
	findings int
	journal  *[]string
}

func (g *lfsJournalGate) InspectLFSObject(context.Context, LFSObjectInfo, []byte) (int, error) {
	*g.journal = append(*g.journal, "content")
	return g.findings, nil
}

// TestLFSServeGateRunsAfterContentGate: on a fetch the content gate looks
// first. An object it blocks never reaches the serve gate; one it lets through
// is then put before the serve gate — on that request and on every later one,
// which the content gate no longer sees.
func TestLFSServeGateRunsAfterContentGate(t *testing.T) {
	type fixture struct {
		b       *Backend
		oid     string
		blob    []byte
		journal []string
		serve   bool // what the serve gate answers
	}
	setup := func(t *testing.T, opts LFSOptions, findings int) *fixture {
		t.Helper()
		f := &fixture{blob: lfsGatedBlob(512), serve: true}
		f.oid = oidOf(f.blob)
		up := newLFSUpstream(t, map[string][]byte{f.oid: f.blob})
		f.b = newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), opts)
		f.b.SetLFSContentGate(&lfsJournalGate{findings: findings, journal: &f.journal})
		f.b.SetLFSServeGate(func(w http.ResponseWriter, _ *http.Request, _ LFSObjectInfo, _ string) bool {
			f.journal = append(f.journal, "serve")
			if !f.serve {
				w.Header().Set("X-Policy-Decision", "block")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, lfsGateRefusal)
			}
			return f.serve
		})
		return f
	}
	get := func(f *fixture) *httptest.ResponseRecorder {
		return doObject(f.b, f.oid, int64(len(f.blob)), "")
	}
	journalIs := func(t *testing.T, f *fixture, want ...string) {
		t.Helper()
		if fmt.Sprint(f.journal) != fmt.Sprint(want) {
			t.Errorf("gates ran as %v, want %v", f.journal, want)
		}
	}

	t.Run("content gate blocks", func(t *testing.T) {
		f := setup(t, LFSOptions{BlockOnFindings: true}, 1)
		// The blocked object is evicted, so the second request is a fetch again
		// and is blocked by the content gate again.
		for i := 1; i <= 2; i++ {
			rr := get(f)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("request %d: status = %d, want 403 from the content gate", i, rr.Code)
			}
			if rr.Body.String() == lfsGateRefusal {
				t.Errorf("request %d: the refusal is the serve gate's, want the content gate's", i)
			}
			assertNoObjectBytes(t, rr.Body.Bytes(), f.blob)
		}
		journalIs(t, f, "content", "content")
		m := f.b.LFSMetrics()
		if m.GateBlocked != 2 || m.ServeRefused != 0 {
			t.Errorf("GateBlocked=%d ServeRefused=%d, want 2/0", m.GateBlocked, m.ServeRefused)
		}
	})

	t.Run("content gate reports without blocking", func(t *testing.T) {
		f := setup(t, LFSOptions{BlockOnFindings: false}, 2)
		for i := 1; i <= 2; i++ {
			if rr := get(f); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), f.blob) {
				t.Fatalf("request %d: status = %d with a %d-byte body, want 200 and the object", i, rr.Code, rr.Body.Len())
			}
		}
		// Fetch: content gate, then serve gate. Cache hit: the serve gate alone.
		journalIs(t, f, "content", "serve", "serve")
	})

	t.Run("content gate passes and the serve gate refuses", func(t *testing.T) {
		f := setup(t, LFSOptions{BlockOnFindings: true}, 0)
		f.serve = false
		rr := get(f)
		assertLFSGateRefusal(t, rr, f.blob)
		journalIs(t, f, "content", "serve")
		m := f.b.LFSMetrics()
		if m.GateBlocked != 0 || m.ServeRefused != 1 {
			t.Errorf("GateBlocked=%d ServeRefused=%d, want 0/1", m.GateBlocked, m.ServeRefused)
		}
	})
}

// TestLFSServeGateUnsetReplacedCleared: without a serve gate objects are served
// as they always were; SetLFSServeGate installs a gate, replaces the one before
// it, and with nil removes it again.
func TestLFSServeGateUnsetReplacedCleared(t *testing.T) {
	blob := lfsGatedBlob(256)
	oid := oidOf(blob)
	size := int64(len(blob))
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})
	served := func(t *testing.T, when string) {
		t.Helper()
		if rr := doObject(b, oid, size, ""); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), blob) {
			t.Fatalf("%s: status = %d with a %d-byte body, want 200 and the object", when, rr.Code, rr.Body.Len())
		}
	}

	served(t, "no gate set")
	if got := b.LFSMetrics().ServeRefused; got != 0 {
		t.Errorf("ServeRefused = %d without a gate, want 0", got)
	}

	refusing := &lfsGateSpy{}
	refusing.refuse.Store(true)
	b.SetLFSServeGate(refusing.gate)
	assertLFSGateRefusal(t, doObject(b, oid, size, ""), blob)

	allowing := &lfsGateSpy{}
	b.SetLFSServeGate(allowing.gate)
	served(t, "gate replaced by one that allows")

	b.SetLFSServeGate(nil)
	served(t, "gate removed")

	if r, a := refusing.count(), allowing.count(); r != 1 || a != 1 {
		t.Errorf("first gate consulted %d times, its replacement %d times; want 1 and 1", r, a)
	}
	m := b.LFSMetrics()
	if m.ServeRefused != 1 || m.BytesServed != 3*size {
		t.Errorf("ServeRefused=%d BytesServed=%d, want 1 and %d", m.ServeRefused, m.BytesServed, 3*size)
	}
}

// TestSetLFSServeGateWithoutLFS: on a backend that does not proxy LFS,
// LFSEnabled reports false and SetLFSServeGate is a no-op — it neither turns
// LFS on nor gets the gate consulted. On one that does, LFSEnabled reports true.
func TestSetLFSServeGateWithoutLFS(t *testing.T) {
	up, err := NewUpstream(UpstreamOptions{
		Name:   "gh",
		URL:    "https://example.com",
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	plain, err := NewBackend(BackendOptions{Upstream: up, Cache: cache.NewMemoryCache(), Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	if plain.LFSEnabled() {
		t.Error("LFSEnabled() = true on a backend without LFS")
	}

	spy := &lfsGateSpy{}
	spy.refuse.Store(true)
	plain.SetLFSServeGate(spy.gate) // must not panic
	if plain.LFSEnabled() {
		t.Error("SetLFSServeGate turned LFS on")
	}
	// The LFS endpoints stay unserved, and the gate is never asked.
	oid := oidOf([]byte("any object"))
	if rr := doObject(plain, oid, 10, ""); rr.Code != http.StatusNotFound {
		t.Errorf("object request on a backend without LFS = %d, want 404", rr.Code)
	}
	if n := spy.count(); n != 0 {
		t.Errorf("gate consulted %d times on a backend without LFS, want 0", n)
	}
	if m := plain.LFSMetrics(); m != (LFSSnapshot{}) {
		t.Errorf("LFS metrics on a backend without LFS = %+v, want zeros", m)
	}

	if with := newLFSBackend(t, "https://example.com", cache.NewMemoryCache(), LFSOptions{}); !with.LFSEnabled() {
		t.Error("LFSEnabled() = false on a backend with LFS")
	}
	var none *Backend
	if none.LFSEnabled() {
		t.Error("LFSEnabled() = true on a nil backend")
	}
}

// lfsHandleCache wraps a cache and counts the content handles it hands out and
// how many of them are closed again.
type lfsHandleCache struct {
	cache.Cache
	opened, closed atomic.Int64
}

func (c *lfsHandleCache) Get(ctx context.Context, key string) (*cache.Entry, error) {
	return c.track(c.Cache.Get(ctx, key))
}

func (c *lfsHandleCache) GetOrLoad(ctx context.Context, key string, loader cache.Loader) (*cache.Entry, error) {
	return c.track(c.Cache.GetOrLoad(ctx, key, loader))
}

func (c *lfsHandleCache) track(entry *cache.Entry, err error) (*cache.Entry, error) {
	if err != nil {
		return entry, err
	}
	// Keep the content seekable: the backend serves ranges from it.
	seeker, ok := entry.Content.(io.ReadSeeker)
	if !ok {
		entry.Content.Close()
		return nil, errors.New("lfsHandleCache: the wrapped cache's content is not seekable")
	}
	c.opened.Add(1)
	entry.Content = &lfsTrackedContent{ReadSeeker: seeker, inner: entry.Content, owner: c}
	return entry, nil
}

type lfsTrackedContent struct {
	io.ReadSeeker
	inner  io.Closer
	owner  *lfsHandleCache
	closed atomic.Bool
}

func (h *lfsTrackedContent) Close() error {
	if h.closed.CompareAndSwap(false, true) {
		h.owner.closed.Add(1)
	}
	return h.inner.Close()
}

// TestLFSServeGateRefusalReleasesTheEntry: a refused request leaves no cache
// entry handle open behind it, whatever the request looked like and whether
// the object was fetched for it or already cached. Afterwards the object can
// still be had: once the gate allows, the same request is served.
func TestLFSServeGateRefusalReleasesTheEntry(t *testing.T) {
	for _, shape := range lfsRequestShapes {
		t.Run(shape.name, func(t *testing.T) {
			blob := lfsGatedBlob(1024)
			oid := oidOf(blob)
			size := int64(len(blob))
			up := newLFSUpstream(t, map[string][]byte{oid: blob})
			c := &lfsHandleCache{Cache: cache.NewMemoryCache()}
			b := newLFSBackend(t, up.srv.URL, c, LFSOptions{})
			spy := &lfsGateSpy{cache: c}
			spy.refuse.Store(true)
			b.SetLFSServeGate(spy.gate)
			balanced := func(t *testing.T, when string) {
				t.Helper()
				if opened, closed := c.opened.Load(), c.closed.Load(); opened == 0 || opened != closed {
					t.Errorf("%s: %d cache entry handles opened, %d closed", when, opened, closed)
				}
			}

			// Refused on the request that fetches the object, then on a cache hit.
			for _, when := range []string{"refused cache miss", "refused cache hit"} {
				rr := lfsObjectRequest(b, shape.method, "o/r.git", oid, size, shape.header(oid))
				assertLFSGateRefusal(t, rr, blob)
				balanced(t, when)
			}

			spy.refuse.Store(false)
			rr := lfsObjectRequest(b, shape.method, "o/r.git", oid, size, shape.header(oid))
			if want := shape.wantBody(blob); rr.Code != shape.wantStatus || !bytes.Equal(rr.Body.Bytes(), want) {
				t.Errorf("once the gate allows: status = %d with a %d-byte body, want %d with %d bytes",
					rr.Code, rr.Body.Len(), shape.wantStatus, len(want))
			}
			balanced(t, "served after the refusals")
			if got := b.LFSMetrics().ServeRefused; got != 2 {
				t.Errorf("ServeRefused = %d, want 2", got)
			}
		})
	}
}

// TestLFSServeGateSilentRefusal: false means not served, whatever the gate did
// or did not write. A gate with no one left to answer — the client went away
// while it was deciding — returns false without writing a refusal; nothing of
// the object is written or counted as served then either, the request is
// counted as refused, and the entry is released.
func TestLFSServeGateSilentRefusal(t *testing.T) {
	blob := lfsGatedBlob(1024)
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	c := &lfsHandleCache{Cache: cache.NewMemoryCache()}
	b := newLFSBackend(t, up.srv.URL, c, LFSOptions{})
	b.SetLFSServeGate(func(http.ResponseWriter, *http.Request, LFSObjectInfo, string) bool { return false })

	for _, shape := range lfsRequestShapes {
		rr := lfsObjectRequest(b, shape.method, "o/r.git", oid, int64(len(blob)), shape.header(oid))
		assertNoObjectBytes(t, rr.Body.Bytes(), blob)
		if cr := rr.Result().Header.Values("Content-Range"); len(cr) != 0 {
			t.Errorf("%s: Content-Range = %q, want no part of the object served", shape.name, cr)
		}
	}
	m := b.LFSMetrics()
	if want := int64(len(lfsRequestShapes)); m.ServeRefused != want || m.BytesServed != 0 {
		t.Errorf("ServeRefused=%d BytesServed=%d, want %d and 0", m.ServeRefused, m.BytesServed, want)
	}
	if opened, closed := c.opened.Load(), c.closed.Load(); opened == 0 || opened != closed {
		t.Errorf("%d cache entry handles opened, %d closed", opened, closed)
	}
}

// TestLFSServeGateMayEvict: the key the gate is handed is enough to act on the
// cached object. A gate that evicts what it refuses — while the backend still
// holds the entry open — leaves nothing cached, so the next request fetches the
// object again and puts it before the gate again.
func TestLFSServeGateMayEvict(t *testing.T) {
	blob := lfsGatedBlob(1024)
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	c := cache.NewMemoryCache()
	b := newLFSBackend(t, up.srv.URL, c, LFSOptions{})
	var evictErrs []error
	b.SetLFSServeGate(func(w http.ResponseWriter, r *http.Request, _ LFSObjectInfo, cacheKey string) bool {
		evictErrs = append(evictErrs, c.Delete(r.Context(), cacheKey))
		w.Header().Set("X-Policy-Decision", "block")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, lfsGateRefusal)
		return false
	})

	for i := 1; i <= 2; i++ {
		assertLFSGateRefusal(t, doObject(b, oid, int64(len(blob)), ""), blob)
		if _, err := c.Stat(context.Background(), "sha256:"+oid); !errors.Is(err, cache.ErrNotFound) {
			t.Errorf("request %d: the evicted object is still cached (stat err = %v)", i, err)
		}
		if got := atomic.LoadInt32(&up.storageHits); got != int32(i) {
			t.Errorf("request %d: upstream storage hits = %d, want %d", i, got, i)
		}
	}
	for i, err := range evictErrs {
		if err != nil {
			t.Errorf("consultation %d: evicting under the gate's cacheKey: %v", i+1, err)
		}
	}
	m := b.LFSMetrics()
	if len(evictErrs) != 2 || m.ServeRefused != 2 || m.CacheMisses != 2 || m.BytesServed != 0 {
		t.Errorf("consultations=%d ServeRefused=%d CacheMisses=%d BytesServed=%d, want 2/2/2/0",
			len(evictErrs), m.ServeRefused, m.CacheMisses, m.BytesServed)
	}
}

// TestLFSServeGateNotConsultedWithoutAnObject: the gate rules on an object that
// is in the cache. A request that never gets that far — a malformed object id,
// a wrong method, a size over the cap, an object the upstream does not have or
// serves corrupted — is answered without it and is not counted as refused.
func TestLFSServeGateNotConsultedWithoutAnObject(t *testing.T) {
	blob := lfsGatedBlob(1024)
	oid := oidOf(blob)
	size := int64(len(blob))
	missing := oidOf([]byte("an object the upstream does not have"))

	cases := []struct {
		name    string
		corrupt bool // the upstream serves other bytes than the object's
		request func(b *Backend) *httptest.ResponseRecorder
		want    int
	}{
		{name: "malformed object id",
			request: func(b *Backend) *httptest.ResponseRecorder { return doObject(b, "not-a-valid-oid", 0, "") },
			want:    http.StatusBadRequest},
		{name: "method not allowed",
			request: func(b *Backend) *httptest.ResponseRecorder {
				return lfsObjectRequest(b, http.MethodPost, "o/r.git", oid, size, nil)
			},
			want: http.StatusMethodNotAllowed},
		{name: "size hint over the cap",
			request: func(b *Backend) *httptest.ResponseRecorder { return doObject(b, oid, 1<<20, "") },
			want:    http.StatusRequestEntityTooLarge},
		{name: "object unknown to the upstream",
			request: func(b *Backend) *httptest.ResponseRecorder { return doObject(b, missing, 36, "") },
			want:    http.StatusBadGateway},
		{name: "upstream serves bytes that do not match the oid", corrupt: true,
			request: func(b *Backend) *httptest.ResponseRecorder { return doObject(b, oid, size, "") },
			want:    http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newLFSUpstream(t, map[string][]byte{oid: blob})
			if tc.corrupt {
				up.corrupt[oid] = []byte("not the bytes the oid stands for")
			}
			b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{MaxObjectBytes: 4096})
			spy := &lfsGateSpy{}
			spy.refuse.Store(true)
			b.SetLFSServeGate(spy.gate)

			rr := tc.request(b)
			if rr.Code != tc.want {
				t.Errorf("status = %d, want %d; body = %q", rr.Code, tc.want, rr.Body.String())
			}
			if n := spy.count(); n != 0 {
				t.Errorf("gate consulted %d times, want 0", n)
			}
			if got := b.LFSMetrics().ServeRefused; got != 0 {
				t.Errorf("ServeRefused = %d, want 0", got)
			}
		})
	}
}

// TestLFSServeGateConcurrentRequests has many clients ask for the same object
// at once, starting from an empty cache, with a gate that refuses every other
// one of them. Each request is put before the gate once and gets the answer the
// gate gave that request: the refusal and nothing else, or the object. Run
// under -race this also covers the gate's place in the request path.
func TestLFSServeGateConcurrentRequests(t *testing.T) {
	blob := lfsGatedBlob(64 << 10)
	oid := oidOf(blob)
	size := int64(len(blob))
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})
	spy := &lfsGateSpy{refuseIf: func(r *http.Request) bool { return r.Header.Get("X-Test-Refuse") != "" }}
	b.SetLFSServeGate(spy.gate)

	const requests = 32
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				rr := lfsObjectRequest(b, http.MethodGet, "o/r.git", oid, size, http.Header{"X-Test-Refuse": {"1"}})
				assertLFSGateRefusal(t, rr, blob)
				return
			}
			rr := lfsObjectRequest(b, http.MethodGet, "o/r.git", oid, size, nil)
			if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), blob) {
				t.Errorf("allowed request: status = %d with a %d-byte body, want 200 and the object", rr.Code, rr.Body.Len())
			}
		}(i)
	}
	wg.Wait()

	if n := spy.count(); n != requests {
		t.Errorf("gate consulted %d times for %d requests", n, requests)
	}
	m := b.LFSMetrics()
	if m.ServeRefused != requests/2 {
		t.Errorf("ServeRefused = %d, want %d", m.ServeRefused, requests/2)
	}
	if want := int64(requests/2) * size; m.BytesServed != want {
		t.Errorf("BytesServed = %d, want %d (only the allowed requests)", m.BytesServed, want)
	}
	if m.ObjectRequests != requests || m.CacheHits+m.CacheMisses != requests {
		t.Errorf("ObjectRequests=%d hits+misses=%d, want %d each", m.ObjectRequests, m.CacheHits+m.CacheMisses, requests)
	}
}
