package git

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// holdGate is a content gate that reports a finding, and — for its first call —
// only once it is released: the window in which an object is in the cache and
// the gate has not decided yet.
type holdGate struct {
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	calls    int
	findings int
	err      error
}

func newHoldGate(findings int) *holdGate {
	return &holdGate{entered: make(chan struct{}), release: make(chan struct{}), findings: findings}
}

func (g *holdGate) InspectLFSObject(context.Context, LFSObjectInfo, []byte) (int, error) {
	g.mu.Lock()
	g.calls++
	first := g.calls == 1
	g.mu.Unlock()
	if first {
		g.once.Do(func() { close(g.entered) })
		<-g.release
	}
	return g.findings, g.err
}

func (g *holdGate) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// An object is in the cache from the moment it is fetched, which is before the
// content gate has looked at it. A second request arriving in that window sees a
// cache hit. It must not be served on the strength of it: "cached" is not
// "gated".
func TestLFSContentGateCannotBeRacedByASecondRequest(t *testing.T) {
	blob := []byte("secret: AKIA_EXAMPLE_KEY")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	gate := newHoldGate(1)
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{BlockOnFindings: true, Gate: gate})

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- doObject(b, oid, int64(len(blob)), "") }()
	<-gate.entered // request 1: the object is cached, its scan is running

	second := doObject(b, oid, int64(len(blob)), "")
	if second.Code != http.StatusForbidden || bytes.Contains(second.Body.Bytes(), blob) {
		t.Fatalf("second request, during the first one's scan: status %d, body %q; an object the gate had not passed was served", second.Code, second.Body.String())
	}
	close(gate.release)
	if rr := <-first; rr.Code != http.StatusForbidden {
		t.Fatalf("first request: status %d, want 403", rr.Code)
	}
	if m := b.LFSMetrics(); m.BytesServed != 0 {
		t.Errorf("%d bytes of a blocked object were served", m.BytesServed)
	}
}

// evictingCache makes an object vanish between a request obtaining its entry
// and the gate reading it: what a concurrent request's refusal does.
type evictingCache struct {
	cache.Cache
	evictOnGet bool
}

func (c *evictingCache) Get(ctx context.Context, key string) (*cache.Entry, error) {
	if c.evictOnGet {
		_ = c.Cache.Delete(ctx, key)
	}
	return c.Cache.Get(ctx, key)
}

// A request that holds an entry the gate can no longer read — because a
// concurrent request's scan refused the object and evicted it — does not get to
// serve it either.
func TestLFSObjectEvictedUnderTheGateIsNotServed(t *testing.T) {
	blob := []byte("secret: AKIA_EXAMPLE_KEY")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	c := &evictingCache{Cache: cache.NewMemoryCache(), evictOnGet: true}
	b := newLFSBackend(t, up.srv.URL, c, LFSOptions{BlockOnFindings: true, Gate: &fakeGate{findings: 0}})

	rr := doObject(b, oid, int64(len(blob)), "")
	if rr.Code != http.StatusForbidden || bytes.Contains(rr.Body.Bytes(), blob) {
		t.Fatalf("status %d, body %q: an object the gate could not read was served under a blocking policy", rr.Code, rr.Body.String())
	}

	// Without a blocking policy the gate only reports, and fails open as before.
	open := newLFSBackend(t, up.srv.URL, &evictingCache{Cache: cache.NewMemoryCache(), evictOnGet: true}, LFSOptions{BlockOnFindings: false, Gate: &fakeGate{findings: 0}})
	if rr := doObject(open, oid, int64(len(blob)), ""); rr.Code != http.StatusOK {
		t.Errorf("report-only policy: status %d, want 200", rr.Code)
	}
}

// The gate decides once per object: a clean object is scanned on its first
// request and served from then on without another scan — and a gate that could
// not decide (a scanner fault) is asked again on the next request rather than
// being remembered as a pass.
func TestLFSContentGateDecidesOncePerObject(t *testing.T) {
	blob := []byte("nothing secret in here")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})

	gate := newHoldGate(0)
	close(gate.release)
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{BlockOnFindings: true, Gate: gate})
	for i := 0; i < 4; i++ {
		if rr := doObject(b, oid, int64(len(blob)), ""); rr.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, rr.Code)
		}
	}
	if n := gate.count(); n != 1 {
		t.Errorf("the gate scanned a clean object %d times, want once", n)
	}

	faulty := newHoldGate(0)
	close(faulty.release)
	faulty.err = errors.New("scanner unavailable")
	fb := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{BlockOnFindings: true, Gate: faulty})
	for i := 0; i < 3; i++ {
		if rr := doObject(fb, oid, int64(len(blob)), ""); rr.Code != http.StatusOK {
			t.Fatalf("request %d with a failing gate: status %d, want 200 (a gate fault fails open)", i+1, rr.Code)
		}
	}
	if n := faulty.count(); n != 3 {
		t.Errorf("a gate that failed was asked %d times over 3 requests, want 3: a fault is not a pass", n)
	}
}

// An object already in the cache when the process starts — fetched by an
// earlier one — has not been gated by this one, and is, on its first request.
func TestLFSContentGateRunsOnAnObjectCachedBeforeStartup(t *testing.T) {
	blob := []byte("secret: AKIA_EXAMPLE_KEY")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	c := cache.NewMemoryCache()
	if _, err := c.Put(context.Background(), lfsCacheKey(oid), bytes.NewReader(blob), nil); err != nil {
		t.Fatal(err)
	}
	gate := &fakeGate{findings: 1}
	b := newLFSBackend(t, up.srv.URL, c, LFSOptions{BlockOnFindings: true, Gate: gate})
	if rr := doObject(b, oid, int64(len(blob)), ""); rr.Code != http.StatusForbidden {
		t.Fatalf("status %d: an object that was already cached was served without the gate", rr.Code)
	}
	if gate.lastOID != oid {
		t.Error("the gate was not consulted for a cache hit")
	}
}

// A serve gate that returns false without writing anything must not leave the
// client with the implicit "200 OK" and an empty body.
func TestLFSServeGateSilentRefusalIsNotA200(t *testing.T) {
	blob := []byte("some object")
	oid := oidOf(blob)
	up := newLFSUpstream(t, map[string][]byte{oid: blob})
	b := newLFSBackend(t, up.srv.URL, cache.NewMemoryCache(), LFSOptions{})
	b.SetLFSServeGate(func(http.ResponseWriter, *http.Request, LFSObjectInfo, string) bool { return false })

	rr := doObject(b, oid, int64(len(blob)), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 for an object that was not admitted and not explicitly refused", rr.Code)
	}
	if bytes.Contains(rr.Body.Bytes(), blob) {
		t.Error("object bytes were written")
	}

	// A gate that wrote its own refusal is left alone.
	b.SetLFSServeGate(func(w http.ResponseWriter, _ *http.Request, _ LFSObjectInfo, _ string) bool {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("refused by the gate"))
		return false
	})
	rr = doObject(b, oid, int64(len(blob)), "")
	if rr.Code != http.StatusForbidden || rr.Body.String() != "refused by the gate" {
		t.Errorf("status %d body %q, want exactly what the gate wrote", rr.Code, rr.Body.String())
	}
}
