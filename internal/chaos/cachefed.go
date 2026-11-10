package chaos

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
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachefed"
)

// cachefedToken is the shared peer-auth secret used by the federation chaos
// scenarios.
const cachefedToken = "chaos-cachefed-token"

func cachefedDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newCacheFedPeer returns a real HTTP server serving the cachefed protocol over
// a memory cache seeded with content under its content-address key, plus the
// key. It is the healthy-sibling fixture for the federation guarantees.
func newCacheFedPeer(content []byte) (*httptest.Server, string, error) {
	c := cache.NewMemoryCache()
	key := cachefedDigest(content)
	if _, err := c.Put(context.Background(), key, strings.NewReader(string(content)), nil); err != nil {
		return nil, "", err
	}
	fed, err := cachefed.New(cachefed.Config{Enabled: true, Serve: true, AuthToken: cachefedToken}, cachefed.NewMetrics())
	if err != nil {
		return nil, "", err
	}
	mux := http.NewServeMux()
	mux.Handle(cachefed.BasePath, fed.Handler(c))
	return httptest.NewServer(mux), key, nil
}

// newCacheFedClient builds a read-through federation pointed at the given peer
// URLs (name "peerN"), with low circuit thresholds and no hedging for
// determinism.
func newCacheFedClient(failureThreshold int, urls ...string) (*cachefed.Federation, error) {
	cfg := cachefed.Config{
		Enabled:          true,
		AuthToken:        cachefedToken,
		MaxPeerFanout:    len(urls),
		FailureThreshold: failureThreshold,
		OpenTimeout:      time.Hour,
	}
	for i, u := range urls {
		cfg.Peers = append(cfg.Peers, cachefed.Peer{Name: fmt.Sprintf("peer%d", i), URL: u})
	}
	return cachefed.New(cfg, cachefed.NewMetrics())
}

func verifyCacheFedPeerHit(ctx context.Context) error {
	content := []byte("FEDERATED-ARTIFACT-BYTES")
	peer, key, err := newCacheFedPeer(content)
	if err != nil {
		return err
	}
	defer peer.Close()

	fed, err := newCacheFedClient(3, peer.URL)
	if err != nil {
		return err
	}
	res, err := fed.Fetch(ctx, key, key)
	if err != nil {
		return fmt.Errorf("Fetch errored: %w", err)
	}
	got, err := io.ReadAll(res.Content)
	res.Content.Close()
	if err != nil {
		return fmt.Errorf("reading verified peer content: %w", err)
	}
	if string(got) != string(content) {
		return fmt.Errorf("peer content = %q, want %q", got, content)
	}
	if snap := fed.Metrics().Snapshot(); snap.Hits != 1 {
		return fmt.Errorf("cachefed hits = %d, want 1", snap.Hits)
	}
	return nil
}

func verifyCacheFedDigestMismatch(ctx context.Context) error {
	// A peer that answers 200 with bytes that do not match the requested digest.
	content := []byte("HONEST-BYTES")
	key := cachefedDigest(content)
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+cachefedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Cachefed-Digest", key)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TAMPERED-REPLACEMENT-PAYLOAD"))
	}))
	defer evil.Close()

	fed, err := newCacheFedClient(3, evil.URL)
	if err != nil {
		return err
	}
	res, err := fed.Fetch(ctx, key, key)
	if err != nil {
		// A pre-stream rejection is also acceptable (nothing served).
		if errors.Is(err, cachefed.ErrNoPeer) || errors.Is(err, cachefed.ErrDigestMismatch) {
			return nil
		}
		return fmt.Errorf("unexpected Fetch error: %w", err)
	}
	_, readErr := io.ReadAll(res.Content)
	res.Content.Close()
	if !errors.Is(readErr, cachefed.ErrDigestMismatch) {
		return fmt.Errorf("tampered peer bytes were accepted (read err = %v, want ErrDigestMismatch)", readErr)
	}
	if snap := fed.Metrics().Snapshot(); snap.VerifyFailures != 1 {
		return fmt.Errorf("verifyFailures = %d, want 1", snap.VerifyFailures)
	}
	return nil
}

func verifyCacheFedPeerDown(ctx context.Context) error {
	// Start a server, capture its URL, then close it so dials are refused.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := down.URL
	down.Close()

	fed, err := newCacheFedClient(3, url)
	if err != nil {
		return err
	}
	key := cachefedDigest([]byte("anything"))
	if _, err := fed.Fetch(ctx, key, key); !errors.Is(err, cachefed.ErrNoPeer) {
		return fmt.Errorf("Fetch err = %v, want ErrNoPeer (caller falls through to upstream)", err)
	}
	if snap := fed.Metrics().Snapshot(); snap.PeerErrors == 0 {
		return errors.New("an unreachable peer did not record a peer error")
	}
	return nil
}

func verifyCacheFedCircuitSheds(ctx context.Context) error {
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer errSrv.Close()

	fed, err := newCacheFedClient(3, errSrv.URL)
	if err != nil {
		return err
	}
	key := cachefedDigest([]byte("whatever"))
	for i := 0; i < 3; i++ {
		if _, err := fed.Fetch(ctx, key, key); !errors.Is(err, cachefed.ErrNoPeer) {
			return fmt.Errorf("attempt %d err = %v, want ErrNoPeer", i, err)
		}
	}
	statuses := fed.PeerStatuses()
	if len(statuses) != 1 || statuses[0].State != "open" {
		return fmt.Errorf("peer state = %+v, want open after %d failures", statuses, 3)
	}
	// With the breaker open the next miss must skip the peer entirely.
	before := fed.Metrics().Snapshot().PeerErrors
	if _, err := fed.Fetch(ctx, key, key); !errors.Is(err, cachefed.ErrNoPeer) {
		return fmt.Errorf("shed fetch err = %v, want ErrNoPeer", err)
	}
	if after := fed.Metrics().Snapshot().PeerErrors; after != before {
		return fmt.Errorf("open circuit still issued a request (peerErrors %d -> %d)", before, after)
	}
	return nil
}
