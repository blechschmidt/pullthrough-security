package homebrew

import (
	"context"
	"sync"
	"time"
)

// brew fetches a formula's image index "immediately before" its bottle only
// when it downloads serially. With HOMEBREW_DOWNLOAD_CONCURRENCY above 1 it
// queues both and sends them in parallel, so the bottle request routinely
// reaches the proxy while the manifest request is still on its way to the
// registry — a few hundred milliseconds too early for the version that manifest
// is about to teach (observed with brew 4.6.20: every bottle request started
// before its manifest response had arrived).
//
// manifestFlights closes that race. It tracks, per repository, the manifest
// fetches currently in progress, and lets a bottle request whose version is not
// yet known wait (briefly, and never longer than a bound) for the one that will
// tell it. Only repositories with a fetch in progress are held, so the structure
// is bounded by the number of concurrent manifest requests.

// manifestWaitTimeout bounds how long a bottle request waits for a manifest
// fetch in progress on its repository. A manifest round trip normally takes a
// few hundred milliseconds; past this bound the bottle request stops waiting
// and falls back to the formula API.
const manifestWaitTimeout = 3 * time.Second

type manifestFlights struct {
	mu      sync.Mutex
	flights map[string]*manifestFlight // keyed by repository
}

// manifestFlight is the set of manifest fetches in progress for one repository.
type manifestFlight struct {
	active int           // fetches in progress
	done   chan struct{} // closed when the last of them ends
}

func newManifestFlights() *manifestFlights {
	return &manifestFlights{flights: make(map[string]*manifestFlight)}
}

// begin records that a manifest fetch for repo has started and returns the
// function that records its end (idempotent). The end must be reported on every
// path, after whatever the manifest teaches has been recorded.
func (f *manifestFlights) begin(repo string) (end func()) {
	f.mu.Lock()
	flight := f.flights[repo]
	if flight == nil {
		flight = &manifestFlight{done: make(chan struct{})}
		f.flights[repo] = flight
	}
	flight.active++
	f.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			flight.active--
			if flight.active == 0 {
				delete(f.flights, repo)
				close(flight.done)
			}
		})
	}
}

// wait blocks until no manifest fetch that was in progress for repo remains,
// the timeout elapses, or ctx is done. It reports whether there was a fetch to
// wait for; when there was none it returns immediately.
func (f *manifestFlights) wait(ctx context.Context, repo string, timeout time.Duration) bool {
	f.mu.Lock()
	flight := f.flights[repo]
	f.mu.Unlock()
	if flight == nil {
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-flight.done:
	case <-timer.C:
	case <-ctx.Done():
	}
	return true
}
