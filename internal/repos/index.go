package repos

import (
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// pinIndex is the in-memory index of the manifests: which cache keys are
// pinned (and by which releases), and which releases contain a coordinate or a
// digest. It is rebuilt from the manifests at startup and updated as they are
// written. IsPinned is consulted by the cache on every eviction decision, so it
// is a single map read under a read lock.
type pinIndex struct {
	mu sync.RWMutex
	// durable are the keys a stored manifest pins.
	durable map[string]*pinEntry
	// pending are keys a running pin job holds between the moment the gateway
	// admitted the object and the moment its manifest is stored: job → keys.
	pending map[string]map[string]struct{}
	held    map[string]int // key → number of jobs holding it
	// contrib is what each manifest ("repo/commit") contributed.
	contrib map[string]*contribution
	// Reverse lookups: coordinate / package / digest → manifest ids.
	byCoord   map[string]map[string]struct{}
	byPackage map[string]map[string]struct{}
	byDigest  map[string]map[string]struct{}
	bytes     int64
}

type pinEntry struct {
	size      int64
	manifests map[string]struct{}
}

type contribution struct {
	tenant  string
	keys    map[string]int64
	coords  []string
	pkgs    []string
	digests []string
}

func newPinIndex() *pinIndex {
	return &pinIndex{
		durable:   map[string]*pinEntry{},
		pending:   map[string]map[string]struct{}{},
		held:      map[string]int{},
		contrib:   map[string]*contribution{},
		byCoord:   map[string]map[string]struct{}{},
		byPackage: map[string]map[string]struct{}{},
		byDigest:  map[string]map[string]struct{}{},
	}
}

// manifestID names a manifest in the index.
func manifestID(repo, commit string) string { return repo + "/" + commit }

func splitManifestID(id string) (repo, commit string) {
	i := strings.LastIndexByte(id, '/')
	if i < 0 {
		return id, ""
	}
	return id[:i], id[i+1:]
}

// coordKey and packageKey normalize a coordinate for lookup.
func coordKey(t, name, version string) string {
	return lockfiles.CanonicalType(t) + "/" + strings.ToLower(strings.TrimSpace(name)) + "@" + strings.ToLower(strings.TrimSpace(version))
}

func packageKey(t, name string) string {
	return lockfiles.CanonicalType(t) + "/" + strings.ToLower(strings.TrimSpace(name))
}

// digestKey normalizes "algo:value" digests for lookup.
func digestKey(algo, value string) string {
	return strings.ToLower(strings.TrimSpace(algo)) + ":" + strings.ToLower(strings.TrimSpace(value))
}

// IsPinned implements cache.PinChecker.
func (x *pinIndex) IsPinned(key string) bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.durable[key] != nil || x.held[key] > 0
}

// pinnedBy returns the manifests pinning key.
func (x *pinIndex) pinnedBy(key string) []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	e := x.durable[key]
	if e == nil {
		return nil
	}
	return sortedKeys(e.manifests)
}

// hold records that job holds key until release.
func (x *pinIndex) hold(job, key string) {
	if key == "" {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	keys := x.pending[job]
	if keys == nil {
		keys = map[string]struct{}{}
		x.pending[job] = keys
	}
	if _, ok := keys[key]; !ok {
		keys[key] = struct{}{}
		x.held[key]++
	}
}

// release drops job's holds.
func (x *pinIndex) release(job string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for key := range x.pending[job] {
		if x.held[key]--; x.held[key] <= 0 {
			delete(x.held, key)
		}
	}
	delete(x.pending, job)
}

// apply indexes a stored manifest, replacing what an earlier version of it
// contributed. Pins only grow: a key an earlier version pinned stays pinned,
// unless it is in drop (an object the release lost).
func (x *pinIndex) apply(m *Manifest, drop ...string) {
	id := manifestID(m.Repo, m.Commit)
	c := &contribution{tenant: m.Tenant, keys: map[string]int64{}}
	seenCoord, seenPkg, seenDigest := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, d := range m.Dependencies {
		if k := coordKey(d.Type, d.Name, d.Version); !seenCoord[k] {
			seenCoord[k] = true
			c.coords = append(c.coords, k)
		}
		if k := packageKey(d.Type, d.Name); !seenPkg[k] {
			seenPkg[k] = true
			c.pkgs = append(c.pkgs, k)
		}
		for _, dg := range d.LockDigests {
			if dg.Algorithm == "" || dg.Value == "" {
				continue
			}
			if k := digestKey(dg.Algorithm, dg.Value); !seenDigest[k] {
				seenDigest[k] = true
				c.digests = append(c.digests, k)
			}
		}
		for _, o := range d.Objects {
			if algo, v, ok := strings.Cut(o.Digest, ":"); ok {
				if k := digestKey(algo, v); !seenDigest[k] {
					seenDigest[k] = true
					c.digests = append(c.digests, k)
				}
			}
			if o.Status == StatusPinned && o.CacheKey != "" {
				c.keys[o.CacheKey] = o.Size
			}
		}
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	dropped := map[string]bool{}
	for _, k := range drop {
		dropped[k] = true
		delete(c.keys, k)
	}
	if old := x.contrib[id]; old != nil {
		for k, size := range old.keys {
			if _, still := c.keys[k]; !still && !dropped[k] {
				c.keys[k] = size // pins only grow
			}
		}
		x.removeLocked(id, old)
	}
	x.contrib[id] = c
	for k, size := range c.keys {
		e := x.durable[k]
		if e == nil {
			e = &pinEntry{size: size, manifests: map[string]struct{}{}}
			x.durable[k] = e
			x.bytes += size
		}
		e.manifests[id] = struct{}{}
	}
	addAll(x.byCoord, c.coords, id)
	addAll(x.byPackage, c.pkgs, id)
	addAll(x.byDigest, c.digests, id)
}

// removeLocked takes a manifest's contribution out of the index.
func (x *pinIndex) removeLocked(id string, c *contribution) {
	for k := range c.keys {
		if e := x.durable[k]; e != nil {
			delete(e.manifests, id)
			if len(e.manifests) == 0 {
				x.bytes -= e.size
				delete(x.durable, k)
			}
		}
	}
	removeAll(x.byCoord, c.coords, id)
	removeAll(x.byPackage, c.pkgs, id)
	removeAll(x.byDigest, c.digests, id)
	delete(x.contrib, id)
}

func addAll(m map[string]map[string]struct{}, keys []string, id string) {
	for _, k := range keys {
		s := m[k]
		if s == nil {
			s = map[string]struct{}{}
			m[k] = s
		}
		s[id] = struct{}{}
	}
}

func removeAll(m map[string]map[string]struct{}, keys []string, id string) {
	for _, k := range keys {
		if s := m[k]; s != nil {
			delete(s, id)
			if len(s) == 0 {
				delete(m, k)
			}
		}
	}
}

// lookup returns the manifests containing a coordinate, a package (version
// empty) or a digest, visible to tenant ("" sees all).
func (x *pinIndex) lookup(tenant, t, name, version, digest string) []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	var set map[string]struct{}
	switch {
	case digest != "":
		algo, v, ok := strings.Cut(digest, ":")
		if !ok {
			return nil
		}
		set = x.byDigest[digestKey(algo, v)]
	case version != "":
		set = x.byCoord[coordKey(t, name, version)]
	default:
		set = x.byPackage[packageKey(t, name)]
	}
	var out []string
	for id := range set {
		if c := x.contrib[id]; c != nil && (tenant == "" || c.tenant == tenant) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// stats returns the number of distinct pinned keys and their bytes.
func (x *pinIndex) stats() (objects int, bytes int64) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return len(x.durable), x.bytes
}

// keys returns every pinned key (for exports).
func (x *pinIndex) keys() []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := make([]string, 0, len(x.durable))
	for k := range x.durable {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
