package nameguard

import (
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// Config configures the name-guard Service. Reference data (popular names,
// internal namespaces, allowlist) is supplied per ecosystem; thresholds and the
// gate action are global.
type Config struct {
	// PopularNames maps an ecosystem to the popular/allowlisted package names that
	// typosquats are measured against. Merged with BuiltinPopular unless
	// DisableBuiltins is set.
	PopularNames map[string][]string
	// InternalNamespaces maps an ecosystem to the private/internal package names
	// and namespace prefixes that a public-registry name must not shadow (the
	// dependency-confusion guard). An entry ending in "*" or "/" — or an npm
	// "@scope" with no name — is treated as a namespace prefix; otherwise an exact
	// package name.
	InternalNamespaces map[string][]string
	// Allowlist maps an ecosystem to names that must never be flagged (legitimate
	// near-neighbors of a popular name). Merged with BuiltinAllow unless
	// DisableBuiltins is set.
	Allowlist map[string][]string
	// DisableBuiltins suppresses the seed BuiltinPopular/BuiltinAllow lists, using
	// only operator-supplied data (for a fully controlled, reproducible policy).
	DisableBuiltins bool

	// DistanceThreshold is the maximum Damerau-Levenshtein distance at which a name
	// is considered a typosquat of a popular name (default 2). The effective
	// threshold is reduced for short names to curb false positives.
	DistanceThreshold int
	// MinNameLength is the shortest name subjected to distance-based typosquat
	// checks; shorter names produce too many coincidental near-matches (default 4).
	MinNameLength int

	// FailSeverity is the minimum finding severity that triggers Action (default
	// high). Empty/none disables severity-based gating.
	FailSeverity Severity
	// WarnSeverity is the minimum severity that triggers a warning below the fail
	// threshold (default medium). Empty/none disables warnings.
	WarnSeverity Severity
	// Action is applied when a finding meets FailSeverity: warn, block, or
	// quarantine. Empty defaults to block.
	Action policy.Action

	// DetectHomoglyphs enables non-ASCII / mixed-script look-alike detection.
	DetectHomoglyphs bool

	// AgeOracle, when set, enables brand-new-package detection. Nil disables it.
	AgeOracle AgeOracle
}

// Snapshot is a point-in-time view of the guard's cumulative counters, surfaced
// through the metrics layer.
type Snapshot struct {
	Inspected           int64
	Flagged             int64
	Blocked             int64
	Warned              int64
	Typosquat           int64
	DependencyConfusion int64
	Homoglyph           int64
	NamespaceMismatch   int64
	NewPackage          int64
}

// Service inspects coordinates and gates pulls. It is immutable after
// construction (reference data is normalized once) and safe for concurrent use.
type Service struct {
	cfg    Config
	logger *slog.Logger
	sets   map[string]*ecosystemSet // ecosystem -> normalized reference data

	counters struct {
		inspected  atomic.Int64
		flagged    atomic.Int64
		blocked    atomic.Int64
		warned     atomic.Int64
		typosquat  atomic.Int64
		depConf    atomic.Int64
		homoglyph  atomic.Int64
		nsMismatch atomic.Int64
		newPackage atomic.Int64
	}
}

// NewService constructs a Service, normalizing the merged reference data per
// ecosystem. It applies defaults for unset thresholds and the gate action.
func NewService(cfg Config, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.DistanceThreshold <= 0 {
		cfg.DistanceThreshold = 2
	}
	if cfg.MinNameLength <= 0 {
		cfg.MinNameLength = 4
	}
	if cfg.Action == "" {
		cfg.Action = policy.ActionBlock
	}
	if cfg.FailSeverity == "" {
		cfg.FailSeverity = SeverityHigh
	}
	if cfg.WarnSeverity == "" {
		cfg.WarnSeverity = SeverityMedium
	}

	popular := mergeLists(cfg.PopularNames, cfg.DisableBuiltins, BuiltinPopular)
	allow := mergeLists(cfg.Allowlist, cfg.DisableBuiltins, BuiltinAllow)

	// The set of ecosystems is the union of every ecosystem named in any input,
	// so an internal-namespace-only ecosystem still gets a reference set.
	ecosystems := map[string]bool{}
	for e := range popular {
		ecosystems[e] = true
	}
	for e := range allow {
		ecosystems[e] = true
	}
	for e := range cfg.InternalNamespaces {
		ecosystems[e] = true
	}

	sets := make(map[string]*ecosystemSet, len(ecosystems))
	for e := range ecosystems {
		sets[e] = newEcosystemSet(e, popular[e], allow[e], cfg.InternalNamespaces[e])
	}

	return &Service{cfg: cfg, logger: logger, sets: sets}
}

// mergeLists merges the per-ecosystem operator lists with the built-in seed
// (unless disabled), de-duplicating within each ecosystem.
func mergeLists(operator map[string][]string, disableBuiltins bool, builtin func() map[string][]string) map[string][]string {
	out := make(map[string][]string)
	if !disableBuiltins {
		for e, names := range builtin() {
			out[e] = append(out[e], names...)
		}
	}
	for e, names := range operator {
		out[e] = append(out[e], names...)
	}
	return out
}

// Inspect evaluates a coordinate and returns a Report of any findings. It never
// returns nil: a clean coordinate yields a Report with no findings. Inspect is
// the pure detection step; gating (mapping findings to an action) is Gate.
func (s *Service) Inspect(art Artifact) *Report {
	s.counters.inspected.Add(1)
	report := &Report{Artifact: art}

	ecosystem := strings.ToLower(strings.TrimSpace(art.Ecosystem))
	set := s.sets[ecosystem]
	rawName := strings.TrimSpace(art.Name)
	if rawName == "" {
		return report
	}
	normalized := normalizeName(ecosystem, rawName)
	if normalized == "" {
		return report
	}

	// (1) Homoglyph / mixed-script: a non-ASCII look-alike is suspicious on its
	// own, and decisively so when its ASCII skeleton matches a known popular name.
	homoglyphImpersonation := false
	if s.cfg.DetectHomoglyphs && hasNonASCII(rawName) {
		if f, ok := s.checkHomoglyph(ecosystem, rawName, normalized, set); ok {
			report.Findings = append(report.Findings, f)
			// When the homoglyph already names the impersonated popular package, the
			// similarity check would only re-report the same impersonation (the
			// non-ASCII name is one substitution from its skeleton), so suppress it.
			homoglyphImpersonation = f.Similar != ""
		}
	}

	// (2) Internal-namespace shadowing (dependency confusion): a public name that
	// collides with a configured private name/prefix.
	if set != nil {
		if f, ok := checkDependencyConfusion(normalized, set); ok {
			report.Findings = append(report.Findings, f)
		}
	}

	// An allowlisted or exactly-popular name is legitimate: skip the similarity
	// heuristics (it cannot typosquat itself), but homoglyph/confusion findings
	// above still stand.
	allowed := set != nil && (set.allow[normalized] || set.popular[normalized] != "")

	if set != nil && !allowed {
		// (3) Typosquat similarity against popular names.
		if f, ok := s.checkTyposquat(normalized, set); ok && !homoglyphImpersonation {
			report.Findings = append(report.Findings, f)
		}
		// (4) Scope/namespace near-miss.
		if f, ok := checkNamespaceMismatch(ecosystem, normalized, set); ok {
			report.Findings = append(report.Findings, f)
		}
	}

	// (5) Brand-new package, when an age oracle is configured. Applied even to
	// allowlisted names is undesirable, so skip when allowed.
	if s.cfg.AgeOracle != nil && !allowed {
		if isNew, ok := s.cfg.AgeOracle.IsNew(ecosystem, normalized); ok && isNew {
			report.Findings = append(report.Findings, Finding{
				Kind:     KindNewPackage,
				Severity: SeverityLow,
				Name:     normalized,
				Reason: fmt.Sprintf("%s package %q is newly published; new packages with no established history warrant review",
					ecosystem, rawName),
			})
		}
	}

	s.recordFindings(report)
	return report
}

// checkHomoglyph builds a homoglyph finding when the raw name carries confusable
// non-ASCII characters. Severity is critical when the ASCII skeleton matches a
// popular name (a deliberate impersonation), otherwise high.
func (s *Service) checkHomoglyph(ecosystem, rawName, normalized string, set *ecosystemSet) (Finding, bool) {
	skeleton, mapped, nonASCII := homoglyphSkeleton(rawName)
	if !nonASCII {
		return Finding{}, false
	}
	normSkeleton := normalizeName(ecosystem, skeleton)

	// Skeleton matches a popular name: a deliberate impersonation, the strongest
	// signal. Otherwise a known look-alike substitution is high severity, while a
	// merely-unmapped non-ASCII letter is medium (it may be a legitimate name).
	if set != nil {
		if canonical, ok := set.popular[normSkeleton]; ok && normSkeleton != normalized {
			return Finding{
				Kind:     KindHomoglyph,
				Severity: SeverityCritical,
				Name:     normalized,
				Similar:  canonical,
				Reason: fmt.Sprintf("%s package name %q uses non-ASCII look-alike characters to impersonate the popular package %q",
					ecosystem, rawName, canonical),
			}, true
		}
	}
	sev := SeverityMedium
	if mapped {
		sev = SeverityHigh
	}
	return Finding{
		Kind:     KindHomoglyph,
		Severity: sev,
		Name:     normalized,
		Reason: fmt.Sprintf("%s package name %q contains non-ASCII look-alike characters (homoglyphs); its ASCII skeleton is %q",
			ecosystem, rawName, normSkeleton),
	}, true
}

// checkDependencyConfusion reports a finding when the normalized public name
// matches a configured internal name or namespace prefix.
func checkDependencyConfusion(normalized string, set *ecosystemSet) (Finding, bool) {
	if set.internal[normalized] {
		return Finding{
			Kind:     KindDependencyConfusion,
			Severity: SeverityCritical,
			Name:     normalized,
			Similar:  normalized,
			Reason: fmt.Sprintf("package %q collides with a configured internal/private package name; a public-registry copy is the classic dependency-confusion attack",
				normalized),
		}, true
	}
	for _, prefix := range set.internalPrefixes {
		if matchesPrefix(normalized, prefix) {
			return Finding{
				Kind:     KindDependencyConfusion,
				Severity: SeverityCritical,
				Name:     normalized,
				Similar:  prefix,
				Reason: fmt.Sprintf("package %q falls under the configured internal namespace %q; a public-registry copy shadows the private registry (dependency confusion)",
					normalized, prefix),
			}, true
		}
	}
	return Finding{}, false
}

// matchesPrefix reports whether a normalized package name falls under a
// configured internal namespace prefix, with boundary awareness so "github.com/
// mycorp" matches "github.com/mycorp/lib" but not the unrelated owner
// "github.com/mycorp-other". A prefix already ending in a separator ("mycorp-",
// "@acme/") is matched literally; a bare segment ("@acme", "github.com/mycorp")
// matches only the segment itself or anything under its "/" boundary.
func matchesPrefix(name, prefix string) bool {
	if prefix == "" {
		return false
	}
	if name == prefix {
		return true
	}
	switch prefix[len(prefix)-1] {
	case '/', '-', '_', '.', '@':
		return strings.HasPrefix(name, prefix)
	default:
		return strings.HasPrefix(name, prefix+"/")
	}
}

// checkTyposquat scans the popular-name list for the nearest match within the
// effective edit-distance threshold, or an exact confusable-substitution
// collision. It returns the single most relevant finding (nearest distance).
func (s *Service) checkTyposquat(normalized string, set *ecosystemSet) (Finding, bool) {
	if len([]rune(normalized)) < s.cfg.MinNameLength {
		return Finding{}, false
	}
	threshold := s.effectiveThreshold(normalized)

	candCanonical := confusableCanonical(normalized)

	bestDist := threshold + 1
	bestName := ""
	confusable := false
	for _, pop := range set.popularList {
		if pop == normalized {
			return Finding{}, false // exact popular match: legitimate
		}
		// Confusable-substitution collision: identical after folding look-alikes.
		if !confusable && candCanonical == confusableCanonical(pop) {
			confusable = true
			bestName = set.popular[pop]
			bestDist = 0
			continue
		}
		d := damerauLevenshtein(normalized, pop, threshold)
		if d > 0 && d < bestDist {
			bestDist = d
			if !confusable {
				bestName = set.popular[pop]
			}
		}
	}

	if confusable {
		return Finding{
			Kind:     KindTyposquat,
			Severity: SeverityHigh,
			Name:     normalized,
			Similar:  bestName,
			Distance: 0,
			Reason: fmt.Sprintf("package %q is visually identical to the popular package %q after normalizing look-alike character substitutions",
				normalized, bestName),
		}, true
	}
	if bestName == "" || bestDist > threshold {
		return Finding{}, false
	}
	sev := SeverityHigh
	if bestDist >= 2 {
		sev = SeverityMedium // two edits away is a weaker (but still notable) signal
	}
	return Finding{
		Kind:     KindTyposquat,
		Severity: sev,
		Name:     normalized,
		Similar:  bestName,
		Distance: bestDist,
		Reason: fmt.Sprintf("package %q is %d edit(s) from the popular package %q and may be a typosquat",
			normalized, bestDist, bestName),
	}, true
}

// effectiveThreshold reduces the configured distance threshold for short names,
// where a fixed threshold of 2 would flag too many coincidental near-matches. A
// name must differ by no more than ~1/4 of its length, capped at the configured
// threshold.
func (s *Service) effectiveThreshold(name string) int {
	n := len([]rune(name))
	t := s.cfg.DistanceThreshold
	switch {
	case n <= 6 && t > 1:
		return 1
	default:
		return t
	}
}

// checkNamespaceMismatch reports a finding when a scoped name's scope is a
// near-miss (edit distance 1) of a known popular scope but not an exact match —
// e.g. npm "@anggular/core" against the known "@angular" scope.
func checkNamespaceMismatch(ecosystem, normalized string, set *ecosystemSet) (Finding, bool) {
	scope := scopeOf(ecosystem, normalized)
	if scope == "" || set.scopes[scope] {
		return Finding{}, false
	}
	for known := range set.scopes {
		// Require a reasonably long scope so single-character scopes don't match
		// everything; distance 1 on a >=5-char scope is a strong signal.
		if len([]rune(known)) < 5 {
			continue
		}
		if damerauLevenshtein(scope, known, 1) == 1 {
			return Finding{
				Kind:     KindNamespaceMismatch,
				Severity: SeverityMedium,
				Name:     normalized,
				Similar:  known,
				Distance: 1,
				Reason: fmt.Sprintf("scope %q is one edit from the known namespace %q; a near-miss scope is a common dependency-confusion/typosquat vector",
					scope, known),
			}, true
		}
	}
	return Finding{}, false
}

// recordFindings accumulates per-kind and aggregate counters for a report.
func (s *Service) recordFindings(report *Report) {
	if !report.Flagged() {
		return
	}
	s.counters.flagged.Add(1)
	for _, f := range report.Findings {
		switch f.Kind {
		case KindTyposquat:
			s.counters.typosquat.Add(1)
		case KindDependencyConfusion:
			s.counters.depConf.Add(1)
		case KindHomoglyph:
			s.counters.homoglyph.Add(1)
		case KindNamespaceMismatch:
			s.counters.nsMismatch.Add(1)
		case KindNewPackage:
			s.counters.newPackage.Add(1)
		}
	}
}

// Decision is the gating outcome for a coordinate's Report.
type Decision struct {
	Action policy.Action
	Code   string
	Reason string
	// Highest is the finding that drove the decision, when any.
	Highest *Finding
}

// Gate maps a Report's worst finding onto an admission decision using the
// configured Fail/Warn severity thresholds, recording the serve-path gate
// counters. A clean (or nil) report allows.
func (s *Service) Gate(report *Report) Decision {
	worst := report.Worst()
	if worst == nil {
		return Decision{Action: policy.ActionAllow, Code: "ok"}
	}
	if s.cfg.FailSeverity != SeverityNone && worst.Severity.AtLeast(s.cfg.FailSeverity) {
		s.countDecision(s.cfg.Action)
		return Decision{
			Action:  s.cfg.Action,
			Code:    string(worst.Kind),
			Reason:  worst.Reason,
			Highest: worst,
		}
	}
	if s.cfg.WarnSeverity != SeverityNone && worst.Severity.AtLeast(s.cfg.WarnSeverity) {
		s.countDecision(policy.ActionWarn)
		return Decision{
			Action:  policy.ActionWarn,
			Code:    string(worst.Kind),
			Reason:  worst.Reason,
			Highest: worst,
		}
	}
	return Decision{Action: policy.ActionAllow, Code: "ok", Highest: worst}
}

// countDecision records the cumulative gate counters for an action.
func (s *Service) countDecision(a policy.Action) {
	switch a {
	case policy.ActionBlock, policy.ActionQuarantine:
		s.counters.blocked.Add(1)
	case policy.ActionWarn:
		s.counters.warned.Add(1)
	}
}

// GateAction returns the action applied when the fail threshold is met.
func (s *Service) GateAction() policy.Action { return s.cfg.Action }

// Metrics returns a snapshot of the cumulative counters.
func (s *Service) Metrics() Snapshot {
	return Snapshot{
		Inspected:           s.counters.inspected.Load(),
		Flagged:             s.counters.flagged.Load(),
		Blocked:             s.counters.blocked.Load(),
		Warned:              s.counters.warned.Load(),
		Typosquat:           s.counters.typosquat.Load(),
		DependencyConfusion: s.counters.depConf.Load(),
		Homoglyph:           s.counters.homoglyph.Load(),
		NamespaceMismatch:   s.counters.nsMismatch.Load(),
		NewPackage:          s.counters.newPackage.Load(),
	}
}
