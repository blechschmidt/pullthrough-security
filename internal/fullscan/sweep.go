package fullscan

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// The backfill sweep. It runs on the leader when it comes to lead and then
// every SweepInterval: it lists the cache, adds every object whose fill
// metadata names an upstream in scope to the inventory (queued as backfill,
// oldest first), and puts back into the queue what needs another reading —
// bytes that changed under their key, an artifact given up on after its
// attempts, one judged under another scan signature, one the ladder evicted
// that is cached again. Tracked artifacts the cache no longer holds are
// dropped. The records of evicted artifacts are kept for EvictedRetention.
//
// An object cached before fill metadata existed cannot be put back before the
// gate (nothing records the path it was served under); it is counted as
// untracked, by the upstream its key names when it names one. Such an object
// is still judged when a client pulls it, and the full mirror reports the ones
// it finds in the cache.

// maybeSweep starts the sweep when it is due.
func (s *Service) maybeSweep(ctx context.Context) {
	now := s.now()
	s.mu.Lock()
	due := s.loaded && !s.sweeping && s.inventory != nil && !now.Before(s.nextSweep)
	if due {
		s.sweeping = true
		s.wg.Add(1)
	}
	inv := s.inventory
	s.mu.Unlock()
	if !due {
		return
	}
	go func() {
		defer s.wg.Done()
		s.sweep(ctx, inv)
	}()
}

// Sweep runs the backfill sweep now (on the leader; tests and operators).
func (s *Service) Sweep(ctx context.Context) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	s.mu.Lock()
	if !s.loaded || s.inventory == nil || s.sweeping {
		s.mu.Unlock()
		return nil
	}
	s.sweeping = true
	s.wg.Add(1)
	inv := s.inventory
	s.mu.Unlock()
	defer s.wg.Done()
	s.sweep(ctx, inv)
	return nil
}

func (s *Service) sweep(ctx context.Context, inv Inventory) {
	start := s.now()
	// The items tracked before the cache is listed: only those can have left
	// it. One a note adds while the listing runs is not in the listing.
	s.mu.Lock()
	known := make(map[string]struct{}, len(s.items))
	for k := range s.items {
		known[k] = struct{}{}
	}
	s.mu.Unlock()
	entries, err := inv.Entries(ctx)
	s.mu.Lock()
	next := s.opts.SweepInterval
	defer func() {
		s.sweeping = false
		s.nextSweep = start.Add(next)
		s.dirty = true
		s.statusCache = nil
		s.mu.Unlock()
		s.kick()
	}()
	if !s.loaded {
		return
	}
	s.st.LastSweep = start.UTC()
	s.overflow = 0
	if err != nil {
		// Try again soon rather than a whole interval later.
		if next > 5*time.Minute {
			next = 5 * time.Minute
		}
		if ctx.Err() == nil {
			s.st.LastSweepError = cleanMessage(err.Error())
			s.log.Warn("full scan: listing the cache for the sweep", "error", err)
		}
		return
	}
	s.st.LastSweepError = ""
	now := s.now()
	sig := s.signatureLocked()
	present := make(map[string]struct{}, len(entries))
	untracked := map[string]int{}
	var fresh, again []*Item
	for _, e := range entries {
		present[e.Key] = struct{}{}
		up := e.Metadata[cache.MetaFillUpstream]
		path := e.Metadata[cache.MetaFillPath]
		if up == "" || path == "" {
			if guess := s.guessUpstream(e.Key); guess != "" {
				untracked[guess]++
			} else {
				untracked[""]++
			}
			continue
		}
		if !s.inScope(up) {
			continue
		}
		digest := e.Metadata[cache.MetaDigest]
		it := s.items[e.Key]
		if it == nil {
			a := Artifact{
				Upstream: up, Path: path, Accept: e.Metadata[cache.MetaFillAccept], Tenant: e.Metadata[cache.MetaFillTenant],
				Key: e.Key, Digest: digest, Size: e.Size, Cached: e.ModTime,
			}
			if !validArtifact(a) {
				untracked[up]++
				continue
			}
			if len(s.items) >= s.opts.MaxItems {
				s.overflow++
				untracked[up]++
				continue
			}
			it = s.newItem(a, now)
			s.items[e.Key] = it
			fresh = append(fresh, it)
			continue
		}
		if it.busy {
			continue
		}
		if ft := e.Metadata[cache.MetaFillTenant]; it.Tenant != ft {
			// The tenant whose request filled the entry is who the scan runs
			// as (with cache namespacing: whose namespace holds it). The one
			// it replaces stays among those who pulled the bytes.
			it.setFillTenant(ft)
			s.putLocked(it)
		}
		switch {
		case digest != "" && it.Digest != "" && digest != it.Digest:
			// Other bytes under the key: judge them, and put them through
			// the gates. Who pulled the old bytes did not pull these.
			it.Digest, it.Size, it.Evicted = digest, e.Size, false
			it.Gates, it.Gate = "", ""
			it.Tenants = nil
			again = append(again, it)
		case it.Evicted:
			// Evicted by the ladder, cached again since (a client's pull was
			// refused and evicted it again, or a release pinned it): judge
			// what is there now.
			it.Evicted = false
			again = append(again, it)
		case it.State == StateError:
			it.Attempts, it.LastError = 0, ""
			again = append(again, it)
		case stale(it, sig):
			bump(&s.countersLocked(it.Upstream).Rescans, "version", 1)
			again = append(again, it)
		case it.State == StatePending && it.hq < 0 && !it.parked:
			again = append(again, it) // lost its place: back in
		default:
			if it.Digest == "" && digest != "" {
				it.Digest = digest
				s.putLocked(it)
			}
		}
	}
	// What the cache no longer holds, and old records of evicted artifacts.
	for key, it := range s.items {
		if it.busy {
			continue
		}
		if it.Evicted {
			if now.Sub(it.EvictedAt) > s.opts.EvictedRetention {
				s.removeLocked(it)
			}
			continue
		}
		if _, was := known[key]; !was {
			continue // noted while the cache was listed
		}
		if _, ok := present[key]; !ok {
			s.countersLocked(it.Upstream).Gone++
			s.removeLocked(it)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return olderFirst(fresh[i], fresh[j]) })
	sort.Slice(again, func(i, j int) bool { return olderFirst(again[i], again[j]) })
	for _, it := range fresh {
		s.enqueueLocked(it, PriorityBackfill, now, time.Time{})
	}
	for _, it := range again {
		if it.State == StatePending {
			// Keeps its place (or gets one back after a restart).
			s.enqueueLocked(it, it.Priority, now, time.Time{})
			s.putLocked(it)
			continue
		}
		s.enqueueLocked(it, PriorityBackfill, now, time.Time{})
	}
	s.st.Untracked = untracked
	s.st.LastSweepFinished = s.now().UTC()
	if len(fresh) > 0 || len(again) > 0 {
		s.log.Info("full scan: backfill sweep", "new", len(fresh), "requeued", len(again), "tracked", len(s.items), "cached", len(entries))
	}
}

// guessUpstream names the upstream an untracked cache key belongs to, when the
// key says ("<upstream>:<path>", optionally under a tenant namespace "<ns>/"),
// for the status's untracked counts.
func (s *Service) guessUpstream(key string) string {
	k := key
	if i := strings.IndexByte(k, '/'); i > 0 && !strings.Contains(k[:i], ":") {
		k = k[i+1:]
	}
	if j := strings.IndexByte(k, ':'); j > 0 && s.inScope(k[:j]) {
		return k[:j]
	}
	return ""
}
