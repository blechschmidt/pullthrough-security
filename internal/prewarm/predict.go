package prewarm

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Reason explains why a target was predicted, for the status surface, metrics,
// and audit.
type Reason string

const (
	// ReasonPatchRelease predicts the next patch release(s) of a frequently-pulled
	// coordinate (the common "a new x.y.Z just shipped" case).
	ReasonPatchRelease Reason = "patch-release"
	// ReasonMinorRelease predicts the next minor release's initial version.
	ReasonMinorRelease Reason = "minor-release"
	// ReasonTransitiveDep predicts a transitive dependency of a recently-pulled
	// top-level package.
	ReasonTransitiveDep Reason = "transitive-dep"
)

// Coordinate is an addressable package artifact: the backend route, its
// ecosystem, name, version, and the full client request path used to fetch it
// (e.g. "/v1/pip/files/.../foo-1.2.3.tar.gz"). Path and Backend are what make a
// coordinate fetchable; Tenant records the namespace the pre-warm should run
// under.
type Coordinate struct {
	Backend   string
	Ecosystem string
	Name      string
	Version   string
	Path      string
	Tenant    string
}

// Target is a predicted future pull the subsystem will proactively fetch+gate.
type Target struct {
	Coordinate
	Reason Reason
	// Score is a rough priority in [0,1] used to order and cap candidates per
	// cycle; higher means warm sooner.
	Score float64
}

// Predictor forecasts likely near-future pulls from observed history.
type Predictor interface {
	Predict(ctx context.Context, now time.Time, stats []CoordStats) []Target
}

// DepSource resolves the direct dependencies of a coordinate (e.g. from the
// provenance/SBOM dependency graph). It is optional; when nil the predictor runs
// the patch-release strategy only. The returned coordinates need only carry
// (Ecosystem, Name, Version) — the predictor fills in the addressable backend
// route and request path by cross-referencing learned history, so it never has
// to synthesize ecosystem-specific URL layouts.
type DepSource interface {
	Dependencies(ctx context.Context, c Coordinate) []Coordinate
}

// HeuristicConfig tunes the built-in predictor.
type HeuristicConfig struct {
	// MinPulls is the minimum number of observed pulls for a coordinate to be
	// considered "frequent" enough to forecast patch releases for.
	MinPulls int
	// RecencyWindow bounds how recently a coordinate must have been pulled to be
	// considered. Zero means no recency filter.
	RecencyWindow time.Duration
	// PatchLookahead is how many successive patch versions to predict past the
	// highest observed version (e.g. 2 predicts z+1 and z+2).
	PatchLookahead int
	// PredictMinor also predicts the next minor release's .0 version.
	PredictMinor bool
	// TransitiveDeps expands recently-pulled top-level packages to their direct
	// dependencies (requires a DepSource).
	TransitiveDeps bool
	// MaxCandidates caps the number of targets a single Predict call returns
	// (highest-scoring first). Zero means unbounded.
	MaxCandidates int
}

// HeuristicPredictor is the built-in, dependency-light predictor. It forecasts:
//
//   - new patch (and optionally minor) releases of frequently- and recently-
//     pulled coordinates, by incrementing the highest observed semver version and
//     substituting it into the learned request path; and
//   - direct dependencies of recently-pulled top-level packages (via an optional
//     DepSource), addressed through request paths learned from history.
//
// A predicted target whose version was already observed (so it is or will be
// cached through ordinary traffic) is never emitted, and a prediction for which
// no fetchable request path can be derived is dropped rather than guessed.
type HeuristicPredictor struct {
	cfg  HeuristicConfig
	deps DepSource
}

// NewHeuristicPredictor constructs the predictor. deps may be nil.
func NewHeuristicPredictor(cfg HeuristicConfig, deps DepSource) *HeuristicPredictor {
	if cfg.PatchLookahead <= 0 {
		cfg.PatchLookahead = 1
	}
	if cfg.MinPulls <= 0 {
		cfg.MinPulls = 1
	}
	return &HeuristicPredictor{cfg: cfg, deps: deps}
}

// Predict implements Predictor.
func (p *HeuristicPredictor) Predict(ctx context.Context, now time.Time, stats []CoordStats) []Target {
	// Index history by (ecosystem, name) so transitive-dep coordinates can borrow
	// a learned backend route + path template to become fetchable.
	index := make(map[string]CoordStats, len(stats))
	for _, cs := range stats {
		index[ecoNameKey(cs.Ecosystem, cs.Name)] = cs
	}

	seen := make(map[string]struct{}) // dedupe targets by backend+path
	var targets []Target

	add := func(t Target) {
		if t.Backend == "" || t.Path == "" {
			return
		}
		k := t.Backend + "\x00" + t.Path
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		targets = append(targets, t)
	}

	for _, cs := range stats {
		if p.cfg.RecencyWindow > 0 && !cs.LastPull.IsZero() &&
			now.Sub(cs.LastPull) > p.cfg.RecencyWindow {
			continue
		}

		// Patch/minor-release forecasting for frequently-pulled coordinates.
		if cs.Pulls >= p.cfg.MinPulls {
			for _, t := range p.predictReleases(cs) {
				add(t)
			}
		}

		// Transitive-dependency forecasting for recently-pulled top-level packages.
		if p.cfg.TransitiveDeps && p.deps != nil {
			hv, hvPath, ok := highestObserved(cs)
			if ok {
				seed := Coordinate{
					Backend: cs.Backend, Ecosystem: cs.Ecosystem, Name: cs.Name,
					Version: hv.String(), Path: hvPath, Tenant: cs.Tenant,
				}
				for _, dep := range p.deps.Dependencies(ctx, seed) {
					if t, ok := p.resolveDepTarget(dep, cs.Tenant, index); ok {
						add(t)
					}
				}
			}
		}
	}

	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].Score != targets[j].Score {
			return targets[i].Score > targets[j].Score
		}
		return targets[i].Path < targets[j].Path
	})
	if p.cfg.MaxCandidates > 0 && len(targets) > p.cfg.MaxCandidates {
		targets = targets[:p.cfg.MaxCandidates]
	}
	return targets
}

// predictReleases forecasts the next patch (and optionally minor) versions for a
// single coordinate.
func (p *HeuristicPredictor) predictReleases(cs CoordStats) []Target {
	hv, hvPath, ok := highestObserved(cs)
	if !ok || hvPath == "" {
		return nil
	}
	// The learned path must embed the exact version so we can substitute the
	// predicted version into it; otherwise we cannot address the new artifact.
	if !strings.Contains(hvPath, hv.String()) {
		return nil
	}
	observed := make(map[string]struct{}, len(cs.Versions))
	for _, v := range cs.Versions {
		observed[v.Version] = struct{}{}
	}

	score := frequencyScore(cs.Pulls)
	var out []Target
	emit := func(v semver, reason Reason, s float64) {
		vs := v.String()
		if _, dup := observed[vs]; dup {
			return
		}
		out = append(out, Target{
			Coordinate: Coordinate{
				Backend:   cs.Backend,
				Ecosystem: cs.Ecosystem,
				Name:      cs.Name,
				Version:   vs,
				Path:      substituteVersion(hvPath, hv.String(), vs),
				Tenant:    cs.Tenant,
			},
			Reason: reason,
			Score:  s,
		})
	}

	for i := 1; i <= p.cfg.PatchLookahead; i++ {
		next := hv
		next.patch += i
		// Successive patches are slightly less likely; decay the score.
		emit(next, ReasonPatchRelease, score*(1.0-0.1*float64(i-1)))
	}
	if p.cfg.PredictMinor {
		emit(semver{major: hv.major, minor: hv.minor + 1, patch: 0}, ReasonMinorRelease, score*0.5)
	}
	return out
}

// resolveDepTarget turns a dependency coordinate into a fetchable target. When
// the dependency already carries a backend route and request path, it is used
// directly; otherwise the predictor borrows a learned path template for the same
// (ecosystem, name) and substitutes the dependency's version into it.
func (p *HeuristicPredictor) resolveDepTarget(dep Coordinate, tenant string, index map[string]CoordStats) (Target, bool) {
	if dep.Name == "" {
		return Target{}, false
	}
	if dep.Backend != "" && dep.Path != "" {
		return Target{Coordinate: withTenant(dep, tenant), Reason: ReasonTransitiveDep, Score: 0.4}, true
	}

	cs, ok := index[ecoNameKey(dep.Ecosystem, dep.Name)]
	if !ok {
		return Target{}, false // never pulled here → no addressable path
	}
	tv, tpath, ok := highestObserved(cs)
	if !ok || tpath == "" {
		return Target{}, false
	}
	// If no concrete version was requested, warm the highest one we know of; if it
	// is already the observed version there is nothing new to warm.
	wantVer := strings.TrimSpace(dep.Version)
	if wantVer == "" {
		return Target{}, false
	}
	for _, v := range cs.Versions {
		if v.Version == wantVer {
			return Target{}, false // already observed/cached
		}
	}
	if !strings.Contains(tpath, tv.String()) {
		return Target{}, false
	}
	return Target{
		Coordinate: Coordinate{
			Backend:   cs.Backend,
			Ecosystem: cs.Ecosystem,
			Name:      cs.Name,
			Version:   wantVer,
			Path:      substituteVersion(tpath, tv.String(), wantVer),
			Tenant:    tenant,
		},
		Reason: ReasonTransitiveDep,
		Score:  0.4,
	}, true
}

func withTenant(c Coordinate, tenant string) Coordinate {
	if c.Tenant == "" {
		c.Tenant = tenant
	}
	return c
}

func ecoNameKey(ecosystem, name string) string { return ecosystem + "\x00" + name }

// substituteVersion replaces every occurrence of the old version string in a
// request path with the new version. It is only called when oldVer is known to
// be present (see predictReleases).
func substituteVersion(path, oldVer, newVer string) string {
	return strings.ReplaceAll(path, oldVer, newVer)
}

// frequencyScore maps a pull count to a [0,1] priority with diminishing returns.
func frequencyScore(pulls int) float64 {
	if pulls <= 0 {
		return 0
	}
	// Saturating curve: 10 pulls ~0.5, 50 ~0.83, 100 ~0.91.
	s := float64(pulls) / float64(pulls+10)
	if s > 1 {
		s = 1
	}
	return s
}

// highestObserved returns the highest parseable release version for a coordinate
// and a representative request path for it. Pre-release versions are considered
// only when no stable release exists.
func highestObserved(cs CoordStats) (semver, string, bool) {
	var best semver
	var bestPath string
	found := false
	for _, v := range cs.Versions {
		sv, ok := parseSemver(v.Version)
		if !ok {
			continue
		}
		if !found || sv.greater(best) {
			best, bestPath, found = sv, v.Path, true
		}
	}
	return best, bestPath, found
}

// semver is a minimal major.minor.patch representation with a pre-release flag.
type semver struct {
	major, minor, patch int
	prerelease          bool
}

func (s semver) String() string {
	return strconv.Itoa(s.major) + "." + strconv.Itoa(s.minor) + "." + strconv.Itoa(s.patch)
}

// greater reports whether s sorts after o, preferring stable over pre-release at
// equal numeric precedence.
func (s semver) greater(o semver) bool {
	if s.major != o.major {
		return s.major > o.major
	}
	if s.minor != o.minor {
		return s.minor > o.minor
	}
	if s.patch != o.patch {
		return s.patch > o.patch
	}
	// Equal numeric precedence: a stable release outranks a pre-release.
	return !s.prerelease && o.prerelease
}

// parseSemver parses "1.2.3", "v1.2.3", "1.2", "1.2.3-rc1", "1.2.3+build". A
// two-component version is treated as major.minor.0. Returns false for anything
// without at least a major.minor numeric core.
func parseSemver(v string) (semver, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if v == "" {
		return semver{}, false
	}
	// Strip build metadata, then detect/strip a pre-release suffix.
	var pre bool
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = true
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return semver{}, false
	}
	nums := make([]int, 3)
	for i := 0; i < 3; i++ {
		if i >= len(parts) {
			nums[i] = 0
			continue
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}
	return semver{major: nums[0], minor: nums[1], patch: nums[2], prerelease: pre}, true
}
