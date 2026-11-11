package cachefed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A peer that answers "I do not have that" or "I will not hand that out" is a
// healthy peer. It must stay in rotation: a sibling that lacked — or had itself
// refused — a few keys in a row used to be cut off from every key for the
// breaker's cooldown.
func TestPeerThatDeclinesAKeyIsNotPenalized(t *testing.T) {
	held := []byte("held by the peer")
	heldKey := sha256Digest(held)

	for _, tc := range []struct {
		name   string
		status int
	}{
		{"does not hold the key (404)", http.StatusNotFound},
		{"declines to serve it (403)", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				asked.Add(1)
				if r.URL.Query().Get("key") == heldKey {
					w.Header().Set(headerDigest, heldKey)
					_, _ = w.Write(held)
					return
				}
				w.WriteHeader(tc.status)
			}))
			defer peer.Close()

			fed, err := New(Config{Enabled: true, AuthToken: "t", MaxPeerFanout: 1, Peers: []Peer{{Name: "p", URL: peer.URL}}}, NewMetrics())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ctx := context.Background()
			// Far more declined keys than the breaker's failure threshold.
			for i := 0; i < 10; i++ {
				missing := sha256Digest([]byte{byte(i)})
				if _, err := fed.Fetch(ctx, missing, missing); !errors.Is(err, ErrNoPeer) {
					t.Fatalf("fetch %d of a declined key: err = %v, want ErrNoPeer", i, err)
				}
			}
			if st := fed.PeerStatuses()[0]; st.State != "closed" {
				t.Fatalf("after ten declined keys the peer's breaker is %q (last error %q), want closed", st.State, st.LastError)
			}
			if snap := fed.Metrics().Snapshot(); snap.PeerErrors != 0 {
				t.Errorf("peer errors = %d: a decline is not an error", snap.PeerErrors)
			}

			// The peer is still asked, and still serves what it has.
			before := asked.Load()
			res, err := fed.Fetch(ctx, heldKey, heldKey)
			if err != nil {
				t.Fatalf("fetching a key the peer holds, after it declined others: %v", err)
			}
			_ = res.Content.Close()
			if asked.Load() == before {
				t.Error("the peer was not asked for the key it holds")
			}
		})
	}
}

// What IS a failure still trips the breaker: a peer that rejects this proxy's
// credentials, or errors.
func TestPeerErrorsStillTripTheBreaker(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError, http.StatusBadGateway} {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		fed, err := New(Config{Enabled: true, AuthToken: "t", MaxPeerFanout: 1, Peers: []Peer{{Name: "p", URL: peer.URL}}}, NewMetrics())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		for i := 0; i < 10; i++ {
			key := sha256Digest([]byte{byte(i)})
			_, _ = fed.Fetch(context.Background(), key, key)
		}
		if st := fed.PeerStatuses()[0]; st.State == "closed" {
			t.Errorf("status %d: the breaker stayed closed after ten failures", status)
		}
		if snap := fed.Metrics().Snapshot(); snap.PeerErrors == 0 {
			t.Errorf("status %d: no peer error was counted", status)
		}
		peer.Close()
	}

	if peerDeclined(nil) || peerDeclined(errors.New("dial tcp: connection refused")) || peerDeclined(&peerStatusError{status: 401}) {
		t.Error("peerDeclined accepted something that is not a decline")
	}
	if !peerDeclined(&peerStatusError{status: 404}) || !peerDeclined(&peerStatusError{status: 403}) {
		t.Error("peerDeclined rejected a 404 or a 403")
	}
}
