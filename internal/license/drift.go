package license

import (
	"strings"
	"sync"
	"time"
)

// DriftEvent records that the declared license of a package changed between two
// of its versions. A license change across versions is a high-signal supply-chain
// risk indicator (a maintainer relicensing, a hijacked release, or an upstream
// that swapped a permissive license for a copyleft one), so it is surfaced to
// operators independently of whether the new license is itself denied.
type DriftEvent struct {
	Ecosystem   string    `json:"ecosystem"`
	Name        string    `json:"name"`
	FromVersion string    `json:"fromVersion"`
	ToVersion   string    `json:"toVersion"`
	FromLicense string    `json:"fromLicense"`
	ToLicense   string    `json:"toLicense"`
	DetectedAt  time.Time `json:"detectedAt"`
}

// pkgLicenses tracks the licenses seen across versions of one package.
type pkgLicenses struct {
	versions    map[string]string // version -> normalized license expression
	lastVersion string            // the most recently observed (distinct) version
	lastLicense string            // its normalized license expression
}

// driftTracker records the license observed for each (ecosystem, package,
// version) and detects when a newly-observed version's license differs from the
// package's previously-recorded license. It is safe for concurrent use and
// bounds its memory: at most maxPackages packages are tracked (LRU-ish: the
// oldest-touched package is evicted) and at most maxEvents recent drift events
// are retained for the admin surface. State is purely in-memory, so it resets on
// restart and requires no external store — suitable for air-gapped operation.
type driftTracker struct {
	mu         sync.Mutex
	packages   map[string]*pkgLicenses
	order      []string // package keys in touch order, for bounded eviction
	maxPkgs    int
	events     []DriftEvent
	maxEvents  int
	totalDrift int64
}

// newDriftTracker constructs a tracker. A non-positive maxEvents defaults to 256;
// the package cap defaults to 50k which bounds memory while comfortably covering
// a large monorepo's dependency surface.
func newDriftTracker(maxEvents int) *driftTracker {
	if maxEvents <= 0 {
		maxEvents = 256
	}
	return &driftTracker{
		packages:  make(map[string]*pkgLicenses),
		maxPkgs:   50000,
		maxEvents: maxEvents,
	}
}

// driftKey is the per-package tracking key (version-independent).
func driftKey(ecosystem, name string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "|" + strings.TrimSpace(name)
}

// observe records the license for one (ecosystem, name, version) observation and
// reports a DriftEvent when the license differs from the package's previously
// recorded (distinct-version) license. Drift is only reported when both the prior
// and current license expressions are non-empty: a transition to/from an
// undeclared license is far more likely to be an extraction gap than a genuine
// relicensing, so it is recorded silently rather than alerted on. The license
// expression is expected pre-normalized by the caller (see normalizeLicense).
func (d *driftTracker) observe(ecosystem, name, version, license string, now time.Time) (DriftEvent, bool) {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return DriftEvent{}, false
	}
	key := driftKey(ecosystem, name)

	d.mu.Lock()
	defer d.mu.Unlock()

	pkg, ok := d.packages[key]
	if !ok {
		pkg = &pkgLicenses{versions: map[string]string{}}
		d.packages[key] = pkg
		d.order = append(d.order, key)
		d.evictLocked()
	} else {
		d.touchLocked(key)
	}

	prevLicense, prevVersion := pkg.lastLicense, pkg.lastVersion
	known, seen := pkg.versions[version]

	// Record the observation (a later re-observation of the same version with a
	// different license also counts as drift — e.g. a mutated/republished release).
	pkg.versions[version] = license

	drift := false
	var ev DriftEvent
	switch {
	case seen && known == license:
		// Same version, same license: nothing changed.
	case version == prevVersion:
		// Re-observing the current version; its license is updated above. Only the
		// cross-version comparison (handled below) signals drift, not this.
	case prevLicense != "" && license != "" && prevLicense != license:
		drift = true
		ev = DriftEvent{
			Ecosystem:   strings.ToLower(strings.TrimSpace(ecosystem)),
			Name:        name,
			FromVersion: prevVersion,
			ToVersion:   version,
			FromLicense: prevLicense,
			ToLicense:   license,
			DetectedAt:  now,
		}
		d.totalDrift++
		d.events = append(d.events, ev)
		if len(d.events) > d.maxEvents {
			d.events = d.events[len(d.events)-d.maxEvents:]
		}
	}

	// Advance the "last seen" pointer to this version (it is the newest observation
	// regardless of semantic ordering; the tracker reasons about observation order,
	// which is what a pull-through proxy actually witnesses).
	pkg.lastVersion = version
	pkg.lastLicense = license

	return ev, drift
}

// touchLocked moves key to the end of the recency order.
func (d *driftTracker) touchLocked(key string) {
	for i, k := range d.order {
		if k == key {
			d.order = append(d.order[:i], d.order[i+1:]...)
			break
		}
	}
	d.order = append(d.order, key)
}

// evictLocked drops the least-recently-touched packages until within the cap.
func (d *driftTracker) evictLocked() {
	for len(d.order) > d.maxPkgs {
		oldest := d.order[0]
		d.order = d.order[1:]
		delete(d.packages, oldest)
	}
}

// recentEvents returns a copy of the retained drift events, most recent first.
func (d *driftTracker) recentEvents() []DriftEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DriftEvent, len(d.events))
	for i, e := range d.events {
		out[len(d.events)-1-i] = e
	}
	return out
}

// normalizeLicense canonicalizes a license expression for drift comparison so
// cosmetic differences (whitespace, operator case, license-id case) do not read
// as drift. It best-effort parses the expression and renders its canonical form;
// an unparsable expression is compared by its trimmed, case-folded text.
func normalizeLicense(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	if e, err := ParseExpression(expr); err == nil {
		return strings.ToLower(e.String())
	}
	return strings.ToLower(strings.Join(strings.Fields(expr), " "))
}
