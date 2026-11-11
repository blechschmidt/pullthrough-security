package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// Concurrent requests for one uncached artifact share a single upstream fetch,
// which runs on behalf of the request that started it. When that request's
// client hangs up, the fetch ends for everyone waiting on it — and a client
// that is still connected must be told so. It used to be answered with nothing
// at all, which the server turns into an empty "200 OK": an empty artifact
// under a success status.
func TestWaiterIsToldWhenTheSharedFetchIsCancelled(t *testing.T) {
	const upstreamPath = "/api/v1/crates/cfg-if/1.0.0/download"
	// Whether the second request joins the first one's fetch or starts its own
	// is a matter of timing; the scenario is repeated until it did join.
	for attempt := 1; ; attempt++ {
		g := newLogGateway(t, logGatewayOptions{})
		hold := make(chan struct{})
		g.stub.mu.Lock()
		g.stub.hold = hold
		g.stub.mu.Unlock()

		// The first client starts the fetch, which the upstream holds open.
		ctx1, cancel1 := context.WithCancel(context.Background())
		req1 := httptest.NewRequest(http.MethodGet, cratePath, nil).WithContext(ctx1)
		req1.RemoteAddr = "10.0.0.1:1"
		done1 := make(chan struct{})
		go func() { defer close(done1); g.handler.ServeHTTP(httptest.NewRecorder(), req1) }()
		for g.stub.count(upstreamPath) == 0 {
			time.Sleep(time.Millisecond)
		}

		// The second client asks for the same artifact and waits on that fetch.
		req2 := httptest.NewRequest(http.MethodGet, cratePath, nil)
		req2.RemoteAddr = "10.0.0.2:1"
		rr2 := httptest.NewRecorder()
		done2 := make(chan struct{})
		go func() { defer close(done2); g.handler.ServeHTTP(rr2, req2) }()
		time.Sleep(100 * time.Millisecond)

		cancel1() // the first client hangs up
		<-done1
		joined := true
		select {
		case <-done2:
		case <-time.After(3 * time.Second):
			joined = false // it had not joined yet and is fetching for itself
		}
		close(hold)
		<-done2
		if !joined || g.stub.count(upstreamPath) != 1 {
			if attempt == 10 {
				t.Fatal("the second request never joined the first one's fetch")
			}
			continue
		}

		if rr2.Code != http.StatusServiceUnavailable || rr2.Header().Get("Retry-After") == "" || rr2.Body.Len() == 0 {
			t.Fatalf("the waiting client was answered with status %d, Retry-After %q and %d body bytes; want a 503 that says to retry",
				rr2.Code, rr2.Header().Get("Retry-After"), rr2.Body.Len())
		}
		// The download log tells the two apart: the client that left, and the
		// one that was sent away.
		byClient := map[string]downloadlog.Entry{}
		for _, e := range g.entries(t) {
			byClient[e.ClientIP] = e
		}
		if e := byClient["10.0.0.1"]; e.Outcome != downloadlog.OutcomeError || e.Status != statusClientClosedRequest {
			t.Errorf("the client that hung up: outcome=%s status=%d, want error/%d", e.Outcome, e.Status, statusClientClosedRequest)
		}
		if e := byClient["10.0.0.2"]; e.Outcome != downloadlog.OutcomeError || e.Status != http.StatusServiceUnavailable || e.Bytes != 0 {
			t.Errorf("the client that was waiting: outcome=%s status=%d bytes=%d, want error/503/0", e.Outcome, e.Status, e.Bytes)
		}

		// And the retry it was asked for works: it starts a fetch of its own.
		retry := g.do(t, http.MethodGet, cratePath, "10.0.0.2:1")
		if retry.Code != http.StatusOK || retry.Body.String() != crateBody {
			t.Fatalf("the retry: status %d, body %q", retry.Code, retry.Body.String())
		}
		return
	}
}
