package policyengine

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed defaultbundle/default.yaml
var defaultBundleFS embed.FS

// Mode controls whether the engine enforces its decisions or only audits them.
type Mode string

const (
	// ModeEnforce applies deny decisions, blocking admission.
	ModeEnforce Mode = "enforce"
	// ModeAudit (dry-run) computes and reports would-be decisions but never
	// blocks: every artifact is admitted while deny decisions are logged and
	// counted. This lets operators validate a new policy bundle in production
	// before turning enforcement on.
	ModeAudit Mode = "audit"
)

// Config configures an Engine.
type Config struct {
	// Dir is the directory of policy bundle files (*.yaml/*.yml/*.json) loaded at
	// startup and on reload. May be empty (only the embedded default applies).
	Dir string
	// Mode selects enforce vs. audit (dry-run). Defaults to enforce.
	Mode Mode
	// DefaultAction is the decision when no rule matches. Defaults to allow.
	DefaultAction Action
	// IncludeDefaultBundle adds the embedded default bundle as a low-priority
	// base so a fresh deployment has sensible supply-chain guardrails even with
	// an empty policy dir. Operator bundles (higher priority) take precedence.
	IncludeDefaultBundle bool
	// ReloadInterval, when > 0, starts a background poller that reloads the
	// policy dir whenever a bundle file changes (by mtime/size).
	ReloadInterval time.Duration
	// Logger is used for load/reload diagnostics.
	Logger *slog.Logger
}

// Snapshot is a point-in-time view of the engine's cumulative counters.
type Snapshot struct {
	Mode           string           `json:"mode"`
	RulesLoaded    int              `json:"rulesLoaded"`
	BundlesLoaded  int              `json:"bundlesLoaded"`
	Evaluations    int64            `json:"evaluations"`
	Allowed        int64            `json:"allowed"`
	Warned         int64            `json:"warned"`
	Denied         int64            `json:"denied"`
	AuditedDenies  int64            `json:"auditedDenies"`
	RuleErrors     int64            `json:"ruleErrors"`
	Reloads        int64            `json:"reloads"`
	ReloadFailures int64            `json:"reloadFailures"`
	LastReloadUnix int64            `json:"lastReloadUnix"`
	DenyByRule     map[string]int64 `json:"denyByRule,omitempty"`
	MatchByRule    map[string]int64 `json:"matchByRule,omitempty"`
}

// Engine is the hot-reloadable policy-as-code admission engine. It is safe for
// concurrent use; the active rule set is swapped atomically on reload so an
// in-flight evaluation always sees a consistent set.
type Engine struct {
	cfg    Config
	logger *slog.Logger

	current atomic.Pointer[RuleSet]

	// counters
	evaluations    atomic.Int64
	allowed        atomic.Int64
	warned         atomic.Int64
	denied         atomic.Int64
	auditedDenies  atomic.Int64
	ruleErrors     atomic.Int64
	reloads        atomic.Int64
	reloadFailures atomic.Int64
	lastReload     atomic.Int64

	mu          sync.Mutex // guards the labeled maps and fingerprint
	denyByRule  map[string]int64
	matchByRule map[string]int64
	fingerprint string // last loaded dir fingerprint (for the poller)

	stopOnce sync.Once
	stopCh   chan struct{}
}

// New constructs an Engine and performs the initial bundle load. A load error
// is returned only when no usable rule set could be produced; otherwise the
// engine starts with whatever compiled successfully. When ReloadInterval > 0 a
// background poller is started; call Close to stop it.
func New(cfg Config) (*Engine, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeEnforce
	}
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = ActionAllow
	}
	e := &Engine{
		cfg:         cfg,
		logger:      cfg.Logger,
		denyByRule:  make(map[string]int64),
		matchByRule: make(map[string]int64),
		stopCh:      make(chan struct{}),
	}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	if cfg.ReloadInterval > 0 {
		go e.watch(cfg.ReloadInterval)
	}
	return e, nil
}

// Mode returns the configured enforcement mode.
func (e *Engine) Mode() Mode { return e.cfg.Mode }

// Dir returns the configured policy directory.
func (e *Engine) Dir() string { return e.cfg.Dir }

// Close stops the background reload poller, if any.
func (e *Engine) Close() error {
	e.stopOnce.Do(func() { close(e.stopCh) })
	return nil
}

// Reload re-reads the policy directory and atomically swaps the active rule set.
// On failure the previous rule set is retained and the error returned, so a bad
// edit never disarms a running policy.
func (e *Engine) Reload() error {
	bundles, fp, err := e.loadBundles()
	if err != nil {
		e.reloadFailures.Add(1)
		e.logger.Error("policyengine: reload failed; keeping previous policy", "error", err)
		return err
	}
	rs, err := CompileRuleSet(bundles, CompileOptions{DefaultAction: e.cfg.DefaultAction})
	if err != nil {
		e.reloadFailures.Add(1)
		e.logger.Error("policyengine: compile failed; keeping previous policy", "error", err)
		return err
	}
	e.current.Store(rs)
	e.reloads.Add(1)
	e.lastReload.Store(time.Now().Unix())
	e.mu.Lock()
	e.fingerprint = fp
	e.mu.Unlock()
	e.logger.Info("policyengine: policy loaded",
		"mode", e.cfg.Mode,
		"bundles", len(rs.Bundles()),
		"rules", rs.RuleCount(),
		"dir", e.cfg.Dir)
	return nil
}

// loadBundles reads and parses all bundle files in the configured dir (plus the
// embedded default when enabled), returning them and a content fingerprint used
// to detect changes.
func (e *Engine) loadBundles() ([]*Bundle, string, error) {
	var bundles []*Bundle
	if e.cfg.IncludeDefaultBundle {
		def, err := DefaultBundle()
		if err != nil {
			return nil, "", err
		}
		bundles = append(bundles, def)
	}

	fp := ""
	if e.cfg.Dir != "" {
		entries, err := os.ReadDir(e.cfg.Dir)
		if err != nil {
			if os.IsNotExist(err) {
				// A missing dir is not fatal: run with just the default bundle.
				e.logger.Warn("policyengine: policy dir does not exist; using default bundle only", "dir", e.cfg.Dir)
				return bundles, fp, nil
			}
			return nil, "", fmt.Errorf("policyengine: read dir %q: %w", e.cfg.Dir, err)
		}
		// Sort for deterministic load order (priority still governs evaluation).
		names := make([]string, 0, len(entries))
		for _, ent := range entries {
			if ent.IsDir() || !isBundleFile(ent.Name()) {
				continue
			}
			names = append(names, ent.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			path := filepath.Join(e.cfg.Dir, name)
			info, err := os.Stat(path)
			if err != nil {
				return nil, "", fmt.Errorf("policyengine: stat %q: %w", path, err)
			}
			fp += fmt.Sprintf("%s:%d:%d;", name, info.Size(), info.ModTime().UnixNano())
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, "", fmt.Errorf("policyengine: read %q: %w", path, err)
			}
			b, err := ParseBundle(data)
			if err != nil {
				return nil, "", fmt.Errorf("policyengine: %q: %w", path, err)
			}
			if b.Name == "" {
				b.Name = name
			}
			b.source = path
			bundles = append(bundles, b)
		}
	}
	return bundles, fp, nil
}

// watch polls the policy dir for changes and reloads on any modification.
func (e *Engine) watch(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-t.C:
			_, fp, err := e.loadBundles()
			if err != nil {
				continue // transient; Reload would log
			}
			e.mu.Lock()
			changed := fp != e.fingerprint
			e.mu.Unlock()
			if changed {
				e.logger.Info("policyengine: detected policy change, reloading", "dir", e.cfg.Dir)
				_ = e.Reload()
			}
		}
	}
}

// Result is the engine's admission outcome for one artifact: the raw rule-set
// Decision plus the action actually enforced after applying the engine's mode.
type Result struct {
	// Decision is the rule-set decision (what the policy says).
	Decision Decision `json:"decision"`
	// EffectiveAction is what is actually enforced. In audit mode a deny is
	// downgraded to allow (the request is admitted) while the would-be deny is
	// recorded.
	EffectiveAction Action `json:"effectiveAction"`
	// Audited is true when audit mode suppressed an otherwise-blocking decision.
	Audited bool `json:"audited"`
	// Mode is the engine mode that produced this result.
	Mode Mode `json:"mode"`
}

// Blocked reports whether admission is actually blocked (false in audit mode).
func (r Result) Blocked() bool { return r.EffectiveAction.Blocked() }

// Evaluate runs the active policy against the input for its tenant and applies
// the engine's enforcement mode. It never returns an error: a malformed rule is
// recorded in the Decision's Errors and counted, but admission still resolves to
// a definite action.
func (e *Engine) Evaluate(ctx context.Context, in Input) Result {
	rs := e.current.Load()
	doc := in.Document()
	dec := rs.evaluate(in.Tenant, doc)

	e.evaluations.Add(1)
	if n := len(dec.Errors); n > 0 {
		e.ruleErrors.Add(int64(n))
	}
	e.recordMatches(dec)

	res := Result{Decision: dec, Mode: e.cfg.Mode, EffectiveAction: dec.Action}
	switch dec.Action {
	case ActionDeny:
		e.denied.Add(1)
		if e.cfg.Mode == ModeAudit {
			res.EffectiveAction = ActionAllow
			res.Audited = true
			e.auditedDenies.Add(1)
		}
	case ActionWarn:
		e.warned.Add(1)
	default:
		e.allowed.Add(1)
	}
	return res
}

// TestEvaluate evaluates the input without mutating any metric counters. It is
// used by the admin "test a policy against a sample input" endpoint so probing
// does not pollute operational metrics.
func (e *Engine) TestEvaluate(in Input) Result {
	rs := e.current.Load()
	dec := rs.evaluate(in.Tenant, in.Document())
	res := Result{Decision: dec, Mode: e.cfg.Mode, EffectiveAction: dec.Action}
	if dec.Action == ActionDeny && e.cfg.Mode == ModeAudit {
		res.EffectiveAction = ActionAllow
		res.Audited = true
	}
	return res
}

func (e *Engine) recordMatches(dec Decision) {
	if len(dec.Matches) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, m := range dec.Matches {
		e.matchByRule[m.RuleID]++
	}
	// Attribute deny reasons only when the decision actually denies.
	if dec.Action == ActionDeny {
		for _, id := range dec.DenyReasons() {
			e.denyByRule[id]++
		}
	}
}

// Snapshot returns the cumulative counters and current load stats.
func (e *Engine) Snapshot() Snapshot {
	rs := e.current.Load()
	e.mu.Lock()
	denyByRule := make(map[string]int64, len(e.denyByRule))
	for k, v := range e.denyByRule {
		denyByRule[k] = v
	}
	matchByRule := make(map[string]int64, len(e.matchByRule))
	for k, v := range e.matchByRule {
		matchByRule[k] = v
	}
	e.mu.Unlock()

	var rules, bundles int
	if rs != nil {
		rules = rs.RuleCount()
		bundles = len(rs.Bundles())
	}
	return Snapshot{
		Mode:           string(e.cfg.Mode),
		RulesLoaded:    rules,
		BundlesLoaded:  bundles,
		Evaluations:    e.evaluations.Load(),
		Allowed:        e.allowed.Load(),
		Warned:         e.warned.Load(),
		Denied:         e.denied.Load(),
		AuditedDenies:  e.auditedDenies.Load(),
		RuleErrors:     e.ruleErrors.Load(),
		Reloads:        e.reloads.Load(),
		ReloadFailures: e.reloadFailures.Load(),
		LastReloadUnix: e.lastReload.Load(),
		DenyByRule:     denyByRule,
		MatchByRule:    matchByRule,
	}
}

// Bundles returns a summary of the currently loaded bundles for the admin
// surface.
func (e *Engine) Bundles() []BundleInfo {
	rs := e.current.Load()
	if rs == nil {
		return nil
	}
	out := make([]BundleInfo, 0, len(rs.Bundles()))
	for _, b := range rs.Bundles() {
		ruleIDs := make([]string, 0, len(b.Rules))
		for _, r := range b.Rules {
			ruleIDs = append(ruleIDs, r.ID)
		}
		out = append(out, BundleInfo{
			Name:        b.Name,
			Description: b.Description,
			Tenant:      b.Tenant,
			Priority:    b.Priority,
			Disabled:    b.Disabled,
			Source:      b.source,
			RuleCount:   len(b.Rules),
			RuleIDs:     ruleIDs,
		})
	}
	return out
}

// BundleInfo is a read-only summary of a loaded bundle.
type BundleInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tenant      string   `json:"tenant,omitempty"`
	Priority    int      `json:"priority"`
	Disabled    bool     `json:"disabled,omitempty"`
	Source      string   `json:"source,omitempty"`
	RuleCount   int      `json:"ruleCount"`
	RuleIDs     []string `json:"ruleIds,omitempty"`
}

// DefaultBundle returns the embedded default policy bundle: a conservative set
// of supply-chain guardrails an operator can adopt as-is or override.
func DefaultBundle() (*Bundle, error) {
	data, err := defaultBundleFS.ReadFile("defaultbundle/default.yaml")
	if err != nil {
		return nil, fmt.Errorf("policyengine: read embedded default bundle: %w", err)
	}
	b, err := ParseBundle(data)
	if err != nil {
		return nil, fmt.Errorf("policyengine: parse embedded default bundle: %w", err)
	}
	if b.Name == "" {
		b.Name = "default"
	}
	b.source = "embedded:default"
	return b, nil
}

func isBundleFile(name string) bool {
	switch filepath.Ext(name) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return false
}
