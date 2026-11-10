package license

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// Outcome is the disposition the policy assigns to a license (or to a whole
// expression after combining its operands). The ordering is significant:
// OutcomeAllowed is the most acceptable and OutcomeDenied the least, which lets
// an OR pick its most-acceptable operand (dual licensing) and an AND surface its
// least-acceptable operand.
type Outcome int

const (
	// OutcomeAllowed: the license is explicitly or by-default permitted.
	OutcomeAllowed Outcome = iota
	// OutcomeUnknown: the license is unrecognized / NOASSERTION. Flagged for
	// review by default (the operator may also choose to allow or deny it).
	OutcomeUnknown
	// OutcomeReview: the license is permitted only after manual review (flagged).
	OutcomeReview
	// OutcomeDenied: the license is prohibited by policy.
	OutcomeDenied
)

// String returns the lowercase token for an outcome.
func (o Outcome) String() string {
	switch o {
	case OutcomeAllowed:
		return "allowed"
	case OutcomeUnknown:
		return "unknown"
	case OutcomeReview:
		return "review"
	case OutcomeDenied:
		return "denied"
	default:
		return "unknown"
	}
}

// parseOutcome maps a config token to an Outcome. It accepts "allow"/"allowed",
// "review"/"flag"/"flagged", "deny"/"denied", and "unknown". Empty maps to the
// supplied default so callers can express "inherit".
func parseOutcome(s string, def Outcome) (Outcome, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return def, nil
	case "allow", "allowed":
		return OutcomeAllowed, nil
	case "review", "flag", "flagged":
		return OutcomeReview, nil
	case "deny", "denied", "block", "blocked":
		return OutcomeDenied, nil
	case "unknown", "noassertion":
		return OutcomeUnknown, nil
	default:
		return def, fmt.Errorf("license: invalid disposition %q (want allow|review|deny|unknown)", s)
	}
}

// parseUnknownOutcome maps the Unknown disposition token to an Outcome. Unlike a
// general outcome, "review"/"flag"/empty resolve to OutcomeUnknown (rather than
// OutcomeReview) so an unrecognized / NOASSERTION license keeps its distinct
// "unknown" identity in the decision code while still being a warn-level flag.
func parseUnknownOutcome(s string) (Outcome, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "review", "flag", "flagged", "unknown", "noassertion":
		return OutcomeUnknown, nil
	case "allow", "allowed":
		return OutcomeAllowed, nil
	case "deny", "denied", "block", "blocked":
		return OutcomeDenied, nil
	default:
		return OutcomeUnknown, fmt.Errorf("license: invalid unknown disposition %q (want allow|review|deny)", s)
	}
}

// parseAction maps a config token to a policy.Action, defaulting an empty value.
func parseAction(s string, def policy.Action) (policy.Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return def, nil
	case "warn":
		return policy.ActionWarn, nil
	case "block":
		return policy.ActionBlock, nil
	case "quarantine":
		return policy.ActionQuarantine, nil
	default:
		return def, fmt.Errorf("license: invalid action %q (want warn|block|quarantine)", s)
	}
}

// PolicyConfig is the operator-facing license policy in primitive form (strings
// and string lists), so a configuration layer can populate it without importing
// the package's Outcome/Action types. A list entry may be an exact SPDX id
// (case-insensitive), a glob with '*' (e.g. "GPL-*"), or an "@family" category
// keyword (e.g. "@strong-copyleft"). Empty scalar fields take the documented
// defaults (or, for a tenant override, inherit the base value).
type PolicyConfig struct {
	// Allow, Deny, Review list the SPDX ids / globs / families that are permitted,
	// prohibited, and permitted-after-review respectively. Deny takes precedence
	// over Review, which takes precedence over Allow when an id matches several.
	Allow  []string
	Deny   []string
	Review []string
	// AllowExceptions lists SPDX exception ids (the operand of WITH) that downgrade
	// an otherwise-denied license to allowed (e.g. "Classpath-exception-2.0" on a
	// GPL license).
	AllowExceptions []string
	// Unknown is the disposition for an unrecognized / NOASSERTION license
	// ("allow"|"review"|"deny"; default "review").
	Unknown string
	// Default is the disposition for a recognized license matching no list
	// ("allow"|"review"|"deny"; default "allow").
	Default string
	// Action is applied when the effective license is denied
	// ("warn"|"block"|"quarantine"; default "block").
	Action string
	// ReviewAction is applied when the effective license is review/unknown
	// ("warn"|"block"|"quarantine"; default "warn").
	ReviewAction string
	// DriftAction is applied when license drift is detected
	// ("warn"|"block"|"quarantine"; default "warn").
	DriftAction string
}

// compiledPolicy is the evaluable form of a PolicyConfig.
type compiledPolicy struct {
	allow      *matcher
	deny       *matcher
	review     *matcher
	exceptions map[string]bool
	unknown    Outcome
	def        Outcome
	action     policy.Action
	review_    policy.Action
	drift      policy.Action
}

// compilePolicy validates a PolicyConfig and compiles it into evaluable form.
func compilePolicy(cfg PolicyConfig) (compiledPolicy, error) {
	unknown, err := parseUnknownOutcome(cfg.Unknown)
	if err != nil {
		return compiledPolicy{}, err
	}
	def, err := parseOutcome(cfg.Default, OutcomeAllowed)
	if err != nil {
		return compiledPolicy{}, err
	}
	action, err := parseAction(cfg.Action, policy.ActionBlock)
	if err != nil {
		return compiledPolicy{}, err
	}
	reviewAct, err := parseAction(cfg.ReviewAction, policy.ActionWarn)
	if err != nil {
		return compiledPolicy{}, err
	}
	driftAct, err := parseAction(cfg.DriftAction, policy.ActionWarn)
	if err != nil {
		return compiledPolicy{}, err
	}
	allow, err := newMatcher(cfg.Allow)
	if err != nil {
		return compiledPolicy{}, fmt.Errorf("license: allow list: %w", err)
	}
	deny, err := newMatcher(cfg.Deny)
	if err != nil {
		return compiledPolicy{}, fmt.Errorf("license: deny list: %w", err)
	}
	review, err := newMatcher(cfg.Review)
	if err != nil {
		return compiledPolicy{}, fmt.Errorf("license: review list: %w", err)
	}
	exceptions := make(map[string]bool, len(cfg.AllowExceptions))
	for _, e := range cfg.AllowExceptions {
		if e = strings.TrimSpace(e); e != "" {
			exceptions[strings.ToLower(e)] = true
		}
	}
	return compiledPolicy{
		allow:      allow,
		deny:       deny,
		review:     review,
		exceptions: exceptions,
		unknown:    unknown,
		def:        def,
		action:     action,
		review_:    reviewAct,
		drift:      driftAct,
	}, nil
}

// leafEval is the evaluation result for a license leaf (or the representative
// leaf an operator picked through OR / surfaced through AND).
type leafEval struct {
	outcome   Outcome
	license   string // canonical license id driving the outcome
	category  Category
	exception string
}

// classifyLeaf evaluates a single license node against the policy. Deny beats
// review beats allow on explicit matches; an unrecognized id falls to the
// unknown disposition and a recognized-but-unlisted id to the default. A WITH
// exception on the allow-exceptions list rescues an otherwise-denied license.
func (p compiledPolicy) classifyLeaf(n licenseNode) leafEval {
	idLower := strings.ToLower(n.id)
	cat, recognized := Classify(n.id)

	var outcome Outcome
	switch {
	case p.deny.match(idLower, cat):
		outcome = OutcomeDenied
	case p.review.match(idLower, cat):
		outcome = OutcomeReview
	case p.allow.match(idLower, cat):
		outcome = OutcomeAllowed
	case !recognized:
		outcome = p.unknown
	default:
		outcome = p.def
	}

	if outcome == OutcomeDenied && n.exception != "" && p.exceptions[strings.ToLower(n.exception)] {
		outcome = OutcomeAllowed
	}

	return leafEval{
		outcome:   outcome,
		license:   CanonicalID(n.id),
		category:  cat,
		exception: n.exception,
	}
}

// evaluate folds the parsed tree into a single leafEval. For OR it returns the
// most-acceptable operand (a consumer may choose any single disjunct — dual
// licensing); for AND it returns the least-acceptable operand (every conjunct's
// obligations apply, so the worst dominates).
func (p compiledPolicy) evaluate(n spdxNode) leafEval {
	switch t := n.(type) {
	case licenseNode:
		return p.classifyLeaf(t)
	case opNode:
		l := p.evaluate(t.left)
		r := p.evaluate(t.right)
		if t.op == "OR" {
			if l.outcome <= r.outcome {
				return l
			}
			return r
		}
		// AND
		if l.outcome >= r.outcome {
			return l
		}
		return r
	default:
		return leafEval{outcome: OutcomeUnknown, license: "NOASSERTION", category: CategoryUnknown}
	}
}

// actionFor maps an outcome to the configured admission action.
func (p compiledPolicy) actionFor(o Outcome) policy.Action {
	switch o {
	case OutcomeDenied:
		return p.action
	case OutcomeReview, OutcomeUnknown:
		return p.review_
	default:
		return policy.ActionAllow
	}
}

// --- matcher ----------------------------------------------------------------

// matcher tests a license id (lower-cased) and its category against a compiled
// set of policy entries: exact ids, '*' globs, and "@family" category keywords.
type matcher struct {
	exact map[string]bool
	globs []string
	cats  map[Category]bool
}

// newMatcher compiles a list of policy entries. Blank entries are skipped.
func newMatcher(entries []string) (*matcher, error) {
	m := &matcher{exact: map[string]bool{}, cats: map[Category]bool{}}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if strings.HasPrefix(e, "@") {
			cats, ok := categoryKeyword(e)
			if !ok {
				return nil, fmt.Errorf("unknown license family %q", e)
			}
			for _, c := range cats {
				m.cats[c] = true
			}
			continue
		}
		if strings.ContainsRune(e, '*') {
			m.globs = append(m.globs, strings.ToLower(e))
			continue
		}
		m.exact[strings.ToLower(e)] = true
	}
	return m, nil
}

// match reports whether idLower (with its category) satisfies any compiled entry.
func (m *matcher) match(idLower string, cat Category) bool {
	if m == nil {
		return false
	}
	if m.exact[idLower] {
		return true
	}
	if m.cats[cat] {
		return true
	}
	for _, g := range m.globs {
		if matchGlob(g, idLower) {
			return true
		}
	}
	return false
}

// matchGlob performs case-insensitive '*' wildcard matching (each '*' matches any
// run, including empty). Inputs are expected lower-cased.
func matchGlob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	// Anchor the first segment.
	if parts[0] != "" {
		if !strings.HasPrefix(s, parts[0]) {
			return false
		}
		s = s[len(parts[0]):]
	}
	// Anchor the last segment.
	last := parts[len(parts)-1]
	if last != "" {
		if !strings.HasSuffix(s, last) {
			return false
		}
		s = s[:len(s)-len(last)]
	}
	// Each interior segment must appear in order.
	for _, seg := range parts[1 : len(parts)-1] {
		if seg == "" {
			continue
		}
		i := strings.Index(s, seg)
		if i < 0 {
			return false
		}
		s = s[i+len(seg):]
	}
	return true
}
