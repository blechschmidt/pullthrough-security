package policyengine

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action is the admission outcome a rule (and the overall decision) carries. It
// mirrors the vocabulary of the hard-coded policy engine (Task 9) so the two can
// be composed by the caller.
type Action string

const (
	// ActionAllow explicitly permits serving the artifact.
	ActionAllow Action = "allow"
	// ActionWarn permits serving but flags the artifact for attention.
	ActionWarn Action = "warn"
	// ActionDeny blocks serving the artifact.
	ActionDeny Action = "deny"
)

// severity orders actions so the most restrictive matched rule wins.
func (a Action) severity() int {
	switch a {
	case ActionDeny:
		return 3
	case ActionWarn:
		return 2
	case ActionAllow:
		return 1
	default:
		return 0
	}
}

// Blocked reports whether the action prevents serving.
func (a Action) Blocked() bool { return a == ActionDeny }

func normalizeAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "allow", "permit":
		return ActionAllow, nil
	case "warn", "flag":
		return ActionWarn, nil
	case "deny", "block":
		return ActionDeny, nil
	}
	return "", fmt.Errorf("unknown action %q (want allow|warn|deny)", s)
}

// Rule is a single declarative admission rule authored by an operator.
type Rule struct {
	// ID uniquely identifies the rule within its bundle (and is the label used
	// in metrics and decision reasons).
	ID string `yaml:"id" json:"id"`
	// Description documents the rule's intent.
	Description string `yaml:"description" json:"description,omitempty"`
	// When is the CEL-subset boolean predicate. When it evaluates true the rule
	// matches and contributes its Action. An empty predicate never matches.
	When string `yaml:"when" json:"when"`
	// Action is the outcome contributed when the rule matches.
	Action Action `yaml:"action" json:"action"`
	// Message is the human-readable reason recorded when the rule matches.
	Message string `yaml:"message" json:"message,omitempty"`
	// Final, when set, short-circuits evaluation: the first matching final rule
	// is decisive and no further rules are consulted. This is how an allow rule
	// whitelists an artifact past later deny rules (or a deny rule hard-stops).
	Final bool `yaml:"final" json:"final,omitempty"`
	// Audit marks an individual rule as dry-run: it is evaluated, matched, and
	// reported, but its action never contributes to the enforced decision. Useful
	// for staging a new deny rule before turning it on.
	Audit bool `yaml:"audit" json:"audit,omitempty"`
}

// Bundle is a named collection of rules loaded from one policy file. A bundle
// may be global or scoped to a single tenant.
type Bundle struct {
	// Name identifies the bundle (defaults to the file name).
	Name string `yaml:"name" json:"name"`
	// Description documents the bundle.
	Description string `yaml:"description" json:"description,omitempty"`
	// Tenant, when non-empty, scopes the bundle to a single tenant (the
	// authenticated principal's team). Empty means the bundle applies to all
	// tenants.
	Tenant string `yaml:"tenant" json:"tenant,omitempty"`
	// Priority orders bundles; higher priority is evaluated first. Tenant-scoped
	// bundles receive a priority boost so per-tenant overrides take precedence
	// over global rules on ties.
	Priority int `yaml:"priority" json:"priority"`
	// Disabled excludes the whole bundle from evaluation without deleting it.
	Disabled bool `yaml:"disabled" json:"disabled,omitempty"`
	// Rules are the bundle's rules, evaluated in declaration order.
	Rules []Rule `yaml:"rules" json:"rules"`

	source string // origin file path, for diagnostics
}

// ParseBundle decodes one YAML/JSON policy bundle document.
func ParseBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("policyengine: decode bundle: %w", err)
	}
	return &b, nil
}

// compiledRule pairs a rule with its compiled predicate and originating bundle.
type compiledRule struct {
	rule     Rule
	bundle   string
	tenant   string
	priority int
	order    int // stable original ordering within the load
	program  *Program
}

// RuleSet is an immutable, compiled set of bundles ready for evaluation. It is
// produced by compiling one or more Bundles and is safe for concurrent use.
type RuleSet struct {
	rules   []compiledRule // pre-sorted by evaluation order
	bundles []*Bundle
	// defaultAction is the decision when no (enforced) rule matches.
	defaultAction Action
}

// CompileOptions tune RuleSet compilation.
type CompileOptions struct {
	// DefaultAction is returned when no enforced rule matches (default allow).
	DefaultAction Action
}

// CompileRuleSet validates and compiles the bundles into an evaluable RuleSet.
// Every rule's predicate is parsed up front so authoring errors are caught at
// load time, never on the admission hot path. Duplicate rule IDs within a single
// bundle are rejected.
func CompileRuleSet(bundles []*Bundle, opts CompileOptions) (*RuleSet, error) {
	def := opts.DefaultAction
	if def == "" {
		def = ActionAllow
	}
	rs := &RuleSet{defaultAction: def}
	order := 0
	for _, b := range bundles {
		if b == nil || b.Disabled {
			if b != nil {
				rs.bundles = append(rs.bundles, b)
			}
			continue
		}
		seen := make(map[string]bool, len(b.Rules))
		priority := b.Priority
		// Tenant-scoped bundles win ties against global bundles.
		if b.Tenant != "" {
			priority += 1000
		}
		for i := range b.Rules {
			r := b.Rules[i]
			if strings.TrimSpace(r.ID) == "" {
				return nil, fmt.Errorf("policyengine: bundle %q rule #%d: missing id", b.Name, i)
			}
			if seen[r.ID] {
				return nil, fmt.Errorf("policyengine: bundle %q: duplicate rule id %q", b.Name, r.ID)
			}
			seen[r.ID] = true

			act, err := normalizeAction(string(r.Action))
			if err != nil {
				return nil, fmt.Errorf("policyengine: bundle %q rule %q: %w", b.Name, r.ID, err)
			}
			r.Action = act

			if strings.TrimSpace(r.When) == "" {
				return nil, fmt.Errorf("policyengine: bundle %q rule %q: empty 'when' predicate", b.Name, r.ID)
			}
			prog, err := Compile(r.When)
			if err != nil {
				return nil, fmt.Errorf("policyengine: bundle %q rule %q: %w", b.Name, r.ID, err)
			}
			rs.rules = append(rs.rules, compiledRule{
				rule:     r,
				bundle:   b.Name,
				tenant:   b.Tenant,
				priority: priority,
				order:    order,
				program:  prog,
			})
			order++
		}
		rs.bundles = append(rs.bundles, b)
	}

	// Evaluation order: highest priority first, then stable load order. This is
	// what makes `final` short-circuit and override precedence deterministic.
	sort.SliceStable(rs.rules, func(i, j int) bool {
		if rs.rules[i].priority != rs.rules[j].priority {
			return rs.rules[i].priority > rs.rules[j].priority
		}
		return rs.rules[i].order < rs.rules[j].order
	})
	return rs, nil
}

// Bundles returns the bundles backing this set (including disabled ones).
func (rs *RuleSet) Bundles() []*Bundle { return rs.bundles }

// RuleCount returns the number of compiled (enabled) rules.
func (rs *RuleSet) RuleCount() int { return len(rs.rules) }

// DefaultAction returns the action used when no enforced rule matches.
func (rs *RuleSet) DefaultAction() Action { return rs.defaultAction }

// RuleMatch records a single rule that matched during evaluation.
type RuleMatch struct {
	RuleID  string `json:"ruleId"`
	Bundle  string `json:"bundle,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
	Action  Action `json:"action"`
	Message string `json:"message,omitempty"`
	// Audit indicates the match did not contribute to the enforced decision
	// because the rule itself is marked audit-only.
	Audit bool `json:"audit,omitempty"`
	// Final indicates this match short-circuited evaluation.
	Final bool `json:"final,omitempty"`
}

// Decision is the outcome of evaluating a RuleSet against an Input document.
type Decision struct {
	// Action is the effective admission action.
	Action Action `json:"action"`
	// Reason is a concise human-readable explanation.
	Reason string `json:"reason"`
	// Matches are all rules that matched, in evaluation order.
	Matches []RuleMatch `json:"matches,omitempty"`
	// Errors records rules whose predicate failed to evaluate (treated as
	// non-matching). They never change the action but are surfaced for debugging.
	Errors []RuleError `json:"errors,omitempty"`
	// Tenant is the tenant the decision was evaluated for.
	Tenant string `json:"tenant,omitempty"`
	// DefaultApplied is true when no enforced rule matched and the default action
	// was used.
	DefaultApplied bool `json:"defaultApplied"`
}

// RuleError records a rule whose predicate evaluation errored.
type RuleError struct {
	RuleID string `json:"ruleId"`
	Bundle string `json:"bundle,omitempty"`
	Error  string `json:"error"`
}

// Allowed reports whether the decision permits serving.
func (d Decision) Allowed() bool { return !d.Action.Blocked() }

// DenyReasons returns the messages/ids of the deny rules that drove a block,
// for metrics and audit. Returns nil when the decision is not a deny.
func (d Decision) DenyReasons() []string {
	if d.Action != ActionDeny {
		return nil
	}
	var out []string
	for _, m := range d.Matches {
		if m.Action == ActionDeny && !m.Audit {
			out = append(out, m.RuleID)
		}
	}
	return out
}

// evaluate runs the rule set against the document for the given tenant. Rules
// scoped to a different tenant are skipped. The semantics are:
//
//   - Rules are visited in priority/order.
//   - The first matching rule with Final=true (and not Audit) is decisive and
//     short-circuits evaluation.
//   - Otherwise the effective action is the most restrictive action among all
//     matching, non-audit rules (deny > warn > allow).
//   - Audit-only rule matches are recorded but never affect the action.
//   - With no enforced match, the rule set's default action applies.
func (rs *RuleSet) evaluate(tenant string, doc map[string]any) Decision {
	d := Decision{Tenant: tenant}
	var effective Action
	var effectiveMsg string
	var effectiveID string
	enforcedMatch := false

	for _, cr := range rs.rules {
		if cr.tenant != "" && cr.tenant != tenant {
			continue
		}
		ok, err := cr.program.EvalBool(doc)
		if err != nil {
			d.Errors = append(d.Errors, RuleError{RuleID: cr.rule.ID, Bundle: cr.bundle, Error: err.Error()})
			continue
		}
		if !ok {
			continue
		}
		match := RuleMatch{
			RuleID:  cr.rule.ID,
			Bundle:  cr.bundle,
			Tenant:  cr.tenant,
			Action:  cr.rule.Action,
			Message: cr.rule.Message,
			Audit:   cr.rule.Audit,
			Final:   cr.rule.Final && !cr.rule.Audit,
		}
		d.Matches = append(d.Matches, match)

		if cr.rule.Audit {
			continue // recorded, but never enforced
		}
		enforcedMatch = true

		if cr.rule.Final {
			effective = cr.rule.Action
			effectiveMsg = cr.rule.Message
			effectiveID = cr.rule.ID
			d.Action = effective
			d.Reason = decisionReason(effective, effectiveID, effectiveMsg, true)
			return d
		}
		if cr.rule.Action.severity() > effective.severity() {
			effective = cr.rule.Action
			effectiveMsg = cr.rule.Message
			effectiveID = cr.rule.ID
		}
	}

	if !enforcedMatch {
		d.Action = rs.defaultAction
		d.DefaultApplied = true
		d.Reason = fmt.Sprintf("no rule matched; default action %q", rs.defaultAction)
		return d
	}
	d.Action = effective
	d.Reason = decisionReason(effective, effectiveID, effectiveMsg, false)
	return d
}

func decisionReason(a Action, id, msg string, final bool) string {
	prefix := id
	if msg != "" {
		prefix = id + ": " + msg
	}
	if final {
		return fmt.Sprintf("%s (final %s)", prefix, a)
	}
	return prefix
}
