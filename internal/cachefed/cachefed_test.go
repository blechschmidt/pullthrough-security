package cachefed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

const testToken = "s3cr3t-peer-token"

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fakePeer is a real HTTP server backed by a memory cache that serves the
// cachefed protocol. It is the sibling proxy end of the federation.
type fakePeer struct {
	srv   *httptest.Server
	cache cache.Cache
	fed   *Federation
}

func newFakePeer(t *testing.T, name, token string) *fakePeer {
	t.Helper()
	c := cache.NewMemoryCache()
	fed, err := New(Config{Enabled: true, Serve: true, AuthToken: token}, NewMetrics())
	if err != nil {
		t.Fatalf("New peer federation: %v", err)
	}
	p := &fakePeer{cache: c, fed: fed}
	mux := http.NewServeMux()
	mux.Handle(BasePath, fed.Handler(c))
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// store puts content into the peer's cache under its content-address key, the
// way the real proxy keys content-addressable artifacts.
func (p *fakePeer) store(t *testing.T, content []byte, meta map[string]string) string {
	t.Helper()
	key := sha256Digest(content)
	if meta == nil {
		meta = map[string]string{}
	}
	if _, err := p.cache.Put(context.Background(), key, strings.NewReader(string(content)), meta); err != nil {
		t.Fatalf("peer cache put: %v", err)
	}
	return key
}

func (p *fakePeer) peerConfig(name string) Peer { return Peer{Name: name, URL: p.srv.URL} }

// newClient builds a read-through Federation pointed at the given peers.
func newClient(t *testing.T, cfg Config, peers ...Peer) *Federation {
	t.Helper()
	cfg.Enabled = true
	cfg.AuthToken = testToken
	cfg.Peers = peers
	fed, err := New(cfg, NewMetrics())
	if err != nil {
		t.Fatalf("New client federation: %v", err)
	}
	return fed
}

func readAll(t *testing.T, r io.ReadCloser) ([]byte, error) {
	t.Helper()
	defer r.Close()
	return io.ReadAll(r)
}

func TestFetchRoundTrip(t *testing.T) {
	peer := newFakePeer(t, "peerA", testToken)
	content := []byte("hello federated world")
	key := peer.store(t, content, map[string]string{
		cache.MetaContentType: "application/octet-stream",
		cache.MetaOrigin:      "https://registry.example/pkg-1.0.0.tgz",
	})

	fed := newClient(t, Config{}, peer.peerConfig("peerA"))
	res, err := fed.Fetch(context.Background(), key, key)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, err := readAll(t, res.Content)
	if err != nil {
		t.Fatalf("read peer content: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content = %q, want %q", got, content)
	}
	if res.Peer != "peerA" {
		t.Errorf("served by %q, want peerA", res.Peer)
	}
	if res.ContentType != "application/octet-stream" {
		t.Errorf("content-type = %q", res.ContentType)
	}
	if res.Origin != "https://registry.example/pkg-1.0.0.tgz" {
		t.Errorf("origin = %q", res.Origin)
	}
	if m := res.Metadata(); m[cache.MetaOrigin] == "" || m[cache.MetaContentType] == "" {
		t.Errorf("metadata not populated: %v", m)
	}
	if snap := fed.Metrics().Snapshot(); snap.Hits != 1 || snap.Misses != 0 {
		t.Errorf("metrics hits/misses = %d/%d, want 1/0", snap.Hits, snap.Misses)
	}
	if snap := peer.fed.Metrics().Snapshot(); snap.Served != 1 {
		t.Errorf("peer served = %d, want 1", snap.Served)
	}
}

func TestFetchMissNoPeerHasKey(t *testing.T) {
	peer := newFakePeer(t, "peerA", testToken)
	fed := newClient(t, Config{}, peer.peerConfig("peerA"))

	// A well-formed digest key the peer does not hold.
	key := sha256Digest([]byte("absent"))
	_, err := fed.Fetch(context.Background(), key, key)
	if !errors.Is(err, ErrNoPeer) {
		t.Fatalf("err = %v, want ErrNoPeer", err)
	}
	// A peer that does not hold the key is a miss, not a peer error: it answered.
	if snap := fed.Metrics().Snapshot(); snap.Misses != 1 || snap.PeerErrors != 0 {
		t.Errorf("misses/peerErrors = %d/%d, want 1/0", snap.Misses, snap.PeerErrors)
	}
}

func TestFetchRejectsTamperedBytes(t *testing.T) {
	peer := newFakePeer(t, "evil", testToken)
	content := []byte("legit content")
	key := sha256Digest(content)
	// Store DIFFERENT bytes under the honest key: a malicious/corrupt peer.
	if _, err := peer.cache.Put(context.Background(), key, strings.NewReader("TAMPERED PAYLOAD"), nil); err != nil {
		t.Fatalf("put: %v", err)
	}

	fed := newClient(t, Config{}, peer.peerConfig("evil"))
	res, err := fed.Fetch(context.Background(), key, key)
	if err != nil {
		t.Fatalf("Fetch returned transport error: %v", err)
	}
	// The mismatch surfaces when the body is read to EOF.
	_, readErr := readAll(t, res.Content)
	if !errors.Is(readErr, ErrDigestMismatch) {
		t.Fatalf("read err = %v, want ErrDigestMismatch", readErr)
	}
	if snap := fed.Metrics().Snapshot(); snap.VerifyFailures != 1 {
		t.Errorf("verifyFailures = %d, want 1", snap.VerifyFailures)
	}
}

func TestFetchRequireDigest(t *testing.T) {
	peer := newFakePeer(t, "peerA", testToken)
	fed := newClient(t, Config{RequireDigest: true}, peer.peerConfig("peerA"))
	// A non-content-addressed key with no expected digest supplied.
	_, err := fed.Fetch(context.Background(), "npm/left-pad/-/left-pad-1.0.0.tgz", "")
	if !errors.Is(err, ErrNoDigest) {
		t.Fatalf("err = %v, want ErrNoDigest", err)
	}
	if snap := fed.Metrics().Snapshot(); snap.SkippedNoDigest != 1 {
		t.Errorf("skippedNoDigest = %d, want 1", snap.SkippedNoDigest)
	}
}

func TestFetchDisabled(t *testing.T) {
	fed, err := New(Config{Enabled: false}, NewMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if fed.Enabled() {
		t.Fatal("Enabled() = true for a disabled federation")
	}
	if _, err := fed.Fetch(context.Background(), "sha256:abc", "sha256:abc"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
}

func TestHandlerUnauthorized(t *testing.T) {
	peer := newFakePeer(t, "peerA", testToken)
	content := []byte("protected")
	key := peer.store(t, content, nil)

	// Client with the wrong token.
	fed := newClient(t, Config{}, peer.peerConfig("peerA"))
	fed.cfg.AuthToken = "wrong-token"

	_, err := fed.Fetch(context.Background(), key, key)
	if !errors.Is(err, ErrNoPeer) {
		t.Fatalf("err = %v, want ErrNoPeer (auth rejected)", err)
	}
	if snap := peer.fed.Metrics().Snapshot(); snap.Unauthorized != 1 {
		t.Errorf("peer unauthorized = %d, want 1", snap.Unauthorized)
	}
}

func TestHandlerServingDisabledWithoutToken(t *testing.T) {
	c := cache.NewMemoryCache()
	// Serve requested but no token configured → serving must be disabled.
	fed, err := New(Config{Enabled: true, Serve: true, AuthToken: ""}, NewMetrics())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fed.Handler(c))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "?key=sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestHandlerHEAD(t *testing.T) {
	peer := newFakePeer(t, "peerA", testToken)
	content := []byte("head me")
	key := peer.store(t, content, map[string]string{cache.MetaContentType: "text/plain"})

	req, _ := http.NewRequest(http.MethodHead, peer.srv.URL+BasePath+"?key="+urlKey(key), nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get(headerDigest) != key {
		t.Errorf("digest header = %q, want %q", resp.Header.Get(headerDigest), key)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("HEAD returned a body of %d bytes", len(body))
	}

	// A HEAD for an absent key is a 404 and a served-miss.
	req2, _ := http.NewRequest(http.MethodHead, peer.srv.URL+BasePath+"?key="+urlKey(sha256Digest([]byte("absent"))), nil)
	req2.Header.Set("Authorization", "Bearer "+testToken)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("HEAD absent status = %d, want 404", resp2.StatusCode)
	}
}

func urlKey(k string) string { return strings.ReplaceAll(k, ":", "%3A") }

func TestSelfExclusion(t *testing.T) {
	peer := newFakePeer(t, "peerA", testToken)
	fed := newClient(t, Config{SelfName: "me"}, peer.peerConfig("me"), peer.peerConfig("peerA"))
	if got := fed.PeerCount(); got != 1 {
		t.Fatalf("PeerCount = %d, want 1 (self excluded)", got)
	}
	names := map[string]bool{}
	for _, s := range fed.PeerStatuses() {
		names[s.Name] = true
	}
	if names["me"] {
		t.Error("self peer 'me' was not excluded")
	}
}

func TestHedgingFastPeerWins(t *testing.T) {
	content := []byte("hedged content payload")
	key := sha256Digest(content)

	// Slow peer: delays before responding. Fast peer: responds immediately.
	slow := newDelayPeer(t, key, content, 200*time.Millisecond)
	fast := newFakePeer(t, "fast", testToken)
	fast.store(t, content, nil)

	// slow is listed first; hedging should still let fast answer.
	fed := newClient(t, Config{MaxPeerFanout: 2, HedgeDelay: 20 * time.Millisecond},
		Peer{Name: "slow", URL: slow.URL}, fast.peerConfig("fast"))

	start := time.Now()
	res, err := fed.Fetch(context.Background(), key, key)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, _ := readAll(t, res.Content)
	elapsed := time.Since(start)
	if string(got) != string(content) {
		t.Fatalf("content mismatch")
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("fetch took %v, hedging should have returned the fast peer well before the slow one", elapsed)
	}
}

// newDelayPeer is a minimal protocol server that sleeps before answering, used
// to exercise hedging deterministically-ish.
func newDelayPeer(t *testing.T, key string, content []byte, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("key") != key {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		time.Sleep(delay)
		w.Header().Set(headerDigest, key)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCircuitBreakerOpensAndSheds(t *testing.T) {
	// A peer that always errors (connection refused via a closed server).
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer dead.Close()

	fed := newClient(t, Config{FailureThreshold: 3, MaxPeerFanout: 1, OpenTimeout: time.Hour},
		Peer{Name: "dead", URL: dead.URL})

	key := sha256Digest([]byte("whatever"))
	for i := 0; i < 3; i++ {
		if _, err := fed.Fetch(context.Background(), key, key); !errors.Is(err, ErrNoPeer) {
			t.Fatalf("attempt %d err = %v, want ErrNoPeer", i, err)
		}
	}
	// The breaker should now be open; the peer is shed (no new request issued).
	statuses := fed.PeerStatuses()
	if len(statuses) != 1 || statuses[0].State != "open" {
		t.Fatalf("peer state = %+v, want open", statuses)
	}
	// Next fetch finds no eligible candidate and returns ErrNoPeer without a new
	// peer error.
	before := fed.Metrics().Snapshot().PeerErrors
	if _, err := fed.Fetch(context.Background(), key, key); !errors.Is(err, ErrNoPeer) {
		t.Fatalf("shed fetch err = %v, want ErrNoPeer", err)
	}
	if after := fed.Metrics().Snapshot().PeerErrors; after != before {
		t.Errorf("open circuit still issued a request (peerErrors %d -> %d)", before, after)
	}
}

func TestConcurrentFetchRace(t *testing.T) {
	peer := newFakePeer(t, "peerA", testToken)
	var keys []string
	for i := 0; i < 20; i++ {
		keys = append(keys, peer.store(t, []byte(fmt.Sprintf("artifact-%d", i)), nil))
	}
	fed := newClient(t, Config{MaxPeerFanout: 2}, peer.peerConfig("peerA"))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := keys[i%len(keys)]
			res, err := fed.Fetch(context.Background(), key, key)
			if err != nil {
				t.Errorf("Fetch: %v", err)
				return
			}
			if _, err := readAll(t, res.Content); err != nil {
				t.Errorf("read: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestContextCancel(t *testing.T) {
	content := []byte("payload")
	key := sha256Digest(content)
	slow := newDelayPeer(t, key, content, 2*time.Second)
	fed := newClient(t, Config{MaxPeerFanout: 1, PeerTimeout: 5 * time.Second},
		Peer{Name: "slow", URL: slow.URL})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := fed.Fetch(ctx, key, key)
	if err == nil {
		t.Fatal("expected a context error")
	}
}

func TestInvalidPeerURL(t *testing.T) {
	_, err := New(Config{Enabled: true, Peers: []Peer{{Name: "bad", URL: "ftp://nope"}}}, NewMetrics())
	if err == nil {
		t.Fatal("expected an error for a non-http peer URL")
	}
}
