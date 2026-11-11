package llmpkgscan

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// Action is what the gate does with a verdict.
type Action string

const (
	// ActionAnnotate records every verdict (finding, admission signal, advisory
	// headers) and always serves the artifact — observe mode.
	ActionAnnotate Action = "annotate"
	// ActionBlock refuses an artifact the model judges malicious (at or above the
	// malicious threshold) with a 403 and quarantines it: the bytes are evicted
	// from the cache so they are neither served nor retained. A suspicious
	// artifact is served with an advisory. This is the default.
	ActionBlock Action = "block"
	// ActionQuarantine does everything ActionBlock does and additionally holds a
	// suspicious artifact (at or above the suspicious threshold): it is refused
	// and evicted until an operator releases it through the break-glass approval
	// workflow.
	ActionQuarantine Action = "quarantine"
)

// Refuses reports whether the action can prevent an artifact from being served.
func (a Action) Refuses() bool { return a == ActionBlock || a == ActionQuarantine }

// FailMode is what the gate does with an artifact it could not get a verdict
// for (provider down, timeout, budget exhausted, unparseable answer, artifact
// too large or not unpackable).
type FailMode string

const (
	// FailOpen serves an unscanned artifact (and says so). The default.
	FailOpen FailMode = "open"
	// FailClosed refuses an unscanned artifact.
	FailClosed FailMode = "closed"
)

// Oversize is what the gate does with an artifact larger than
// Limits.MaxArtifactBytes.
type Oversize string

const (
	// OversizeFail does not scan such an artifact at all: it is reported
	// "oversized" and the fail mode decides. A verdict is then always a verdict
	// on every byte that is served. The default.
	OversizeFail Oversize = "fail"
	// OversizeMetadataOnly examines what can be established within the scan
	// limits — the artifact's inventory, the install-time scripts and manifests
	// found in its first MaxArtifactBytes, and for an OCI image the image config
	// and the inventory of every layer that fits — and has the model judge that.
	// The verdict is recorded with scope "metadata-only", flagged truncated, and
	// carries a finding saying the artifact was only partially examined: it is
	// evidence about what was read, not a statement about what was not.
	OversizeMetadataOnly Oversize = "metadata-only"
)

// Mode selects how the model is shown the package.
type Mode string

const (
	// ModeAuto uses tools when the provider supports them, else a single-shot
	// content bundle. The default.
	ModeAuto Mode = "auto"
	// ModeTools requires tool use; it is a configuration error with a provider
	// that lacks it.
	ModeTools Mode = "tools"
	// ModeBundle always uses the single-shot content bundle, e.g. for an
	// OpenAI-compatible gateway whose model has no function calling.
	ModeBundle Mode = "bundle"
)

// Built-in defaults. Each bound exists because the corresponding quantity is
// controlled by whoever published the package.
const (
	DefaultMaliciousThreshold  = 0.7
	DefaultSuspiciousThreshold = 0.5

	defaultTimeout             = 120 * time.Second
	defaultMaxArtifactBytes    = int64(64 << 20)
	defaultMaxUnpackedBytes    = int64(256 << 20)
	defaultMaxFileBytes        = int64(1 << 20)
	defaultMaxFiles            = 5000
	defaultMaxDepth            = 32
	defaultMaxCompressionRatio = 200.0
	defaultMaxPromptBytes      = 120 << 10
	defaultMaxToolResultBytes  = 24 << 10
	defaultMaxToolBytes        = 256 << 10
	defaultMaxTurns            = 8
	defaultMaxToolCalls        = 24
	defaultMaxOutputTokens     = 16000
	defaultMaxTotalTokens      = 600000
	defaultMaxConcurrent       = 4
	defaultMaxRetries          = 1
	defaultRetryBaseDelay      = 500 * time.Millisecond
	defaultErrorTTL            = 5 * time.Minute
	defaultBudgetWindow        = 24 * time.Hour

	// retainedTextCap bounds the file content one scan keeps in memory. Text is
	// what the model can read; binary members are kept as a description only.
	retainedTextCap = int64(32 << 20)
)

// Limits bounds one scan.
type Limits struct {
	// MaxArtifactBytes is the largest (compressed) artifact the gate will scan
	// whole. What happens to a larger one is Config.Oversize: by default it is
	// not scanned at all — it is reported "oversized" and handled by the fail
	// mode — because a verdict on a prefix would be a verdict on something other
	// than what is served; under "metadata-only" its inventory and the scripts
	// within this many bytes are examined and the verdict says so. For an OCI
	// image the bound applies to each layer.
	MaxArtifactBytes int64
	// MaxUnpackedBytes caps the decompressed bytes produced while unpacking.
	MaxUnpackedBytes int64
	// MaxFileBytes caps the bytes retained per file.
	MaxFileBytes int64
	// MaxFiles caps the archive members examined.
	MaxFiles int
	// MaxDepth caps the directory depth of a member's path.
	MaxDepth int
	// MaxCompressionRatio is the decompression-bomb guard.
	MaxCompressionRatio float64

	// MaxPromptBytes bounds the package material in the first prompt: the seed in
	// tool mode, the whole bundle in bundle mode.
	MaxPromptBytes int
	// MaxToolResultBytes bounds one tool result; MaxToolBytes bounds all of them.
	MaxToolResultBytes int
	MaxToolBytes       int
	// MaxTurns caps model turns; MaxToolCalls caps tool invocations.
	MaxTurns     int
	MaxToolCalls int
	// MaxOutputTokens bounds one model response; MaxTotalTokens bounds the tokens
	// (input and output, every turn) one scan may consume.
	MaxOutputTokens int
	MaxTotalTokens  int
}

// DefaultLimits returns the built-in bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxArtifactBytes:    defaultMaxArtifactBytes,
		MaxUnpackedBytes:    defaultMaxUnpackedBytes,
		MaxFileBytes:        defaultMaxFileBytes,
		MaxFiles:            defaultMaxFiles,
		MaxDepth:            defaultMaxDepth,
		MaxCompressionRatio: defaultMaxCompressionRatio,
		MaxPromptBytes:      defaultMaxPromptBytes,
		MaxToolResultBytes:  defaultMaxToolResultBytes,
		MaxToolBytes:        defaultMaxToolBytes,
		MaxTurns:            defaultMaxTurns,
		MaxToolCalls:        defaultMaxToolCalls,
		MaxOutputTokens:     defaultMaxOutputTokens,
		MaxTotalTokens:      defaultMaxTotalTokens,
	}
}

// withDefaults fills zero fields. Only an exact zero takes the default, so a
// negative value survives to be rejected by validate.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxArtifactBytes == 0 {
		l.MaxArtifactBytes = d.MaxArtifactBytes
	}
	if l.MaxUnpackedBytes == 0 {
		l.MaxUnpackedBytes = d.MaxUnpackedBytes
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxFiles == 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxCompressionRatio == 0 {
		l.MaxCompressionRatio = d.MaxCompressionRatio
	}
	if l.MaxPromptBytes == 0 {
		l.MaxPromptBytes = d.MaxPromptBytes
	}
	if l.MaxToolResultBytes == 0 {
		l.MaxToolResultBytes = d.MaxToolResultBytes
	}
	if l.MaxToolBytes == 0 {
		l.MaxToolBytes = d.MaxToolBytes
	}
	if l.MaxTurns == 0 {
		l.MaxTurns = d.MaxTurns
	}
	if l.MaxToolCalls == 0 {
		l.MaxToolCalls = d.MaxToolCalls
	}
	if l.MaxOutputTokens == 0 {
		l.MaxOutputTokens = d.MaxOutputTokens
	}
	if l.MaxTotalTokens == 0 {
		l.MaxTotalTokens = d.MaxTotalTokens
	}
	return l
}

// Hard floors and ceilings. A limit outside them is a misconfiguration: too low
// and no real package can be scanned, too high and the bound stops bounding.
const (
	minPromptBytes     = 4 << 10
	minToolResultBytes = 1 << 10
	maxTurnsCeiling    = 64
	maxToolCallCeiling = 512
)

func (l Limits) validate() error {
	switch {
	case l.MaxArtifactBytes < 0, l.MaxUnpackedBytes < 0, l.MaxFileBytes < 0:
		return errors.New("llmpkgscan: byte limits must not be negative")
	case l.MaxFiles < 0, l.MaxDepth < 0:
		return errors.New("llmpkgscan: maxFiles and maxDepth must not be negative")
	case l.MaxCompressionRatio < 1:
		return fmt.Errorf("llmpkgscan: maxCompressionRatio must be at least 1, got %g", l.MaxCompressionRatio)
	case l.MaxPromptBytes < minPromptBytes:
		return fmt.Errorf("llmpkgscan: maxPromptBytes must be at least %d", minPromptBytes)
	case l.MaxToolResultBytes < minToolResultBytes:
		return fmt.Errorf("llmpkgscan: maxToolResultBytes must be at least %d", minToolResultBytes)
	case l.MaxToolBytes < l.MaxToolResultBytes:
		return errors.New("llmpkgscan: maxToolBytes must not be smaller than maxToolResultBytes")
	case l.MaxTurns < 1 || l.MaxTurns > maxTurnsCeiling:
		return fmt.Errorf("llmpkgscan: maxTurns must be within [1,%d], got %d", maxTurnsCeiling, l.MaxTurns)
	case l.MaxToolCalls < 0 || l.MaxToolCalls > maxToolCallCeiling:
		return fmt.Errorf("llmpkgscan: maxToolCalls must be within [0,%d], got %d", maxToolCallCeiling, l.MaxToolCalls)
	case l.MaxOutputTokens < 256:
		return errors.New("llmpkgscan: maxOutputTokens must be at least 256")
	case l.MaxTotalTokens < l.MaxOutputTokens:
		return errors.New("llmpkgscan: maxTotalTokens must not be smaller than maxOutputTokens")
	}
	return nil
}

// BudgetConfig bounds what the gate may spend on the provider. Scanning is
// driven by what clients pull, so without a ceiling a tenant pulling a large
// dependency tree — or anyone deliberately requesting many distinct artifacts —
// runs up an unbounded bill.
type BudgetConfig struct {
	// Enabled turns budget enforcement on.
	Enabled bool
	// GlobalCeilingUSD caps spend across all tenants per window (0 = unlimited).
	GlobalCeilingUSD float64
	// TenantCeilingUSD caps each tenant's spend per window (0 = unlimited).
	TenantCeilingUSD float64
	// TenantCeilingsUSD overrides TenantCeilingUSD for specific tenants.
	TenantCeilingsUSD map[string]float64
	// Window is the period after which usage resets (0 => 24h).
	Window time.Duration
}

// Config configures the gate.
type Config struct {
	// Enabled gates whether the service is built and wired into the pull path.
	Enabled bool
	// Provider is the LLM backend, shared with (or built like) the commit
	// scanner's. Required.
	Provider commit.Provider
	// Model is the provider-specific model identifier. Required.
	Model string
	// Mode selects tools vs. a single-shot bundle. Default auto.
	Mode Mode
	// Thinking requests extended reasoning from the provider.
	Thinking bool

	// Action is applied to a verdict. Default block.
	Action Action
	// FailMode is applied when no verdict could be obtained. Default open.
	FailMode FailMode
	// Oversize is applied to an artifact larger than Limits.MaxArtifactBytes.
	// Default fail (the fail mode decides).
	Oversize Oversize
	// MaliciousThreshold is the minimum confidence at which a "malicious" verdict
	// is acted on as malicious; below it the artifact is treated as suspicious.
	// SuspiciousThreshold is the minimum confidence at which a "suspicious"
	// verdict is flagged; below it the artifact is treated as benign.
	MaliciousThreshold  float64
	SuspiciousThreshold float64

	// Timeout is the wall-clock bound on one scan, queueing included.
	Timeout time.Duration
	// Limits bounds one scan.
	Limits Limits
	// Include, when non-empty, is the set of ecosystems scanned; empty selects
	// DefaultEcosystems. Exclude removes ecosystems and always wins.
	Include []string
	Exclude []string
	// ExcludeUpstreams names upstreams (backends) whose artifacts are never
	// scanned, whatever their ecosystem. Scanning sends package contents to the
	// LLM provider; this is how a private registry's packages are kept from
	// leaving the network while the public registries of the same ecosystem are
	// still scanned. Names are matched exactly.
	ExcludeUpstreams []string

	// Budget bounds provider spend; Pricing prices tokens (nil => the commit
	// scanner's built-in table).
	Budget  BudgetConfig
	Pricing *commit.Pricing

	// Store persists verdicts. Nil keeps them in memory (lost on restart).
	Store VerdictStore
	// CacheTTL, when positive, expires a stored verdict after this age so the
	// artifact is scanned again. Zero keeps verdicts indefinitely: the bytes
	// behind a digest never change.
	CacheTTL time.Duration
	// ErrorTTL is how long a failed scan is remembered before the same artifact
	// is tried again. It keeps an artifact that reliably fails (too large, not
	// unpackable, an answer the parser rejects) from costing a scan per request.
	ErrorTTL time.Duration
	// MaxConcurrent bounds the scans in flight.
	MaxConcurrent int
	// MaxRetries is the number of extra attempts after a transient provider
	// error; RetryBaseDelay is the base of the exponential backoff between them.
	// A negative MaxRetries disables retries.
	MaxRetries     int
	RetryBaseDelay time.Duration

	// OnVerdict, when set, is called once for each freshly produced verdict (not
	// on a cache hit), after it is stored. It must not block.
	OnVerdict func(v *Verdict)
	// OnBudgetExhausted, when set, is called when a scan is skipped because a
	// budget is spent. scope is "tenant" or "global". It must not block.
	OnBudgetExhausted func(scope, tenant string)

	// Logger is used for diagnostics; nil uses slog.Default().
	Logger *slog.Logger
	// Now supplies the clock (tests). Nil uses time.Now.
	Now func() time.Time
}

// EcosystemGitLFS is the ecosystem key of Git LFS objects. Git clones and
// fetches are not this gate's: their commits are the LLM commit-scan pipeline's
// (internal/scan/commit). The large objects an LFS pointer stands for never
// appear in a commit's diff, so they are examined here, under a key of their
// own that can be included or excluded independently.
const EcosystemGitLFS = "git-lfs"

// DefaultEcosystems is the set scanned when Include is empty: every ecosystem
// the proxy fronts whose artifacts reach a client through this gate. The gate
// is off unless enabled; once on, an ecosystem is left out only by naming it in
// Exclude — a backend added later is covered without anyone remembering to opt
// it in.
var DefaultEcosystems = []string{
	"npm", "pip", "cargo", "go", "nuget", "maven", "rubygems", "composer",
	"helm", "apt", "yum", "terraform", "conan", "conda", "cran", "cpan",
	"hex", "bazel", "julia", "jsr", "hackage", "nix", "homebrew", "ansible",
	"puppet", "swift", "dart", "openvsx", "huggingface", "docker", "generic",
	EcosystemGitLFS,
}

// CanonEcosystem normalizes an ecosystem alias to the key used for matching.
// The aliases include the alternative upstream type names ("deb", "rpm",
// "pub"), which is what the gateway reports as the ecosystem of an upstream
// configured under them.
func CanonEcosystem(eco string) string {
	switch e := strings.ToLower(strings.TrimSpace(eco)); e {
	case "deb":
		return "apt"
	case "rpm":
		return "yum"
	case "pub":
		return "dart"
	case "oci":
		return "docker"
	case "lfs", "gitlfs":
		return EcosystemGitLFS
	case "pypi", "python":
		return "pip"
	case "gem", "gems", "ruby":
		return "rubygems"
	case "crates", "crate", "rust":
		return "cargo"
	case "node", "nodejs":
		return "npm"
	case "packagist", "php":
		return "composer"
	case "dotnet", ".net":
		return "nuget"
	case "golang":
		return "go"
	case "java", "gradle":
		return "maven"
	default:
		return e
	}
}

// trimList trims, de-duplicates and drops empty entries, preserving order.
func trimList(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

// upstreamExcluded reports whether an upstream is exempt from scanning.
func (c Config) upstreamExcluded(upstream string) bool {
	if upstream == "" {
		return false
	}
	for _, u := range c.ExcludeUpstreams {
		if u == upstream {
			return true
		}
	}
	return false
}

func canonList(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, e := range in {
		c := CanonEcosystem(e)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// withDefaults fills zero-valued fields and normalizes enums.
func (c Config) withDefaults() Config {
	c.Mode = Mode(strings.ToLower(strings.TrimSpace(string(c.Mode))))
	if c.Mode == "" {
		c.Mode = ModeAuto
	}
	c.Action = Action(strings.ToLower(strings.TrimSpace(string(c.Action))))
	if c.Action == "" {
		c.Action = ActionBlock
	}
	c.FailMode = FailMode(strings.ToLower(strings.TrimSpace(string(c.FailMode))))
	if c.FailMode == "" {
		c.FailMode = FailOpen
	}
	c.Oversize = Oversize(strings.ToLower(strings.TrimSpace(string(c.Oversize))))
	if c.Oversize == "" {
		c.Oversize = OversizeFail
	}
	if c.MaliciousThreshold == 0 {
		c.MaliciousThreshold = DefaultMaliciousThreshold
	}
	if c.SuspiciousThreshold == 0 {
		c.SuspiciousThreshold = DefaultSuspiciousThreshold
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	c.Limits = c.Limits.withDefaults()
	c.Include = canonList(c.Include)
	if len(c.Include) == 0 {
		c.Include = canonList(DefaultEcosystems)
	}
	c.Exclude = canonList(c.Exclude)
	c.ExcludeUpstreams = trimList(c.ExcludeUpstreams)
	if c.Budget.Window == 0 {
		c.Budget.Window = defaultBudgetWindow
	}
	if c.Pricing == nil {
		c.Pricing = commit.DefaultPricing()
	}
	if c.ErrorTTL == 0 {
		c.ErrorTTL = defaultErrorTTL
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = defaultMaxConcurrent
	}
	switch {
	case c.MaxRetries < 0:
		c.MaxRetries = 0
	case c.MaxRetries == 0:
		c.MaxRetries = defaultMaxRetries
	}
	if c.RetryBaseDelay <= 0 {
		c.RetryBaseDelay = defaultRetryBaseDelay
	}
	c.Model = strings.TrimSpace(c.Model)
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	if c.Provider == nil {
		return errors.New("llmpkgscan: a provider is required")
	}
	if c.Model == "" {
		return errors.New("llmpkgscan: a model is required")
	}
	switch c.Mode {
	case ModeAuto, ModeBundle:
	case ModeTools:
		if _, ok := c.Provider.(commit.ToolProvider); !ok {
			return fmt.Errorf("llmpkgscan: mode %q requires a provider with tool use, and %q has none", c.Mode, c.Provider.Name())
		}
	default:
		return fmt.Errorf("llmpkgscan: invalid mode %q (want auto|tools|bundle)", c.Mode)
	}
	switch c.Action {
	case ActionAnnotate, ActionBlock, ActionQuarantine:
	default:
		return fmt.Errorf("llmpkgscan: invalid action %q (want annotate|quarantine|block)", c.Action)
	}
	switch c.FailMode {
	case FailOpen, FailClosed:
	default:
		return fmt.Errorf("llmpkgscan: invalid failMode %q (want open|closed)", c.FailMode)
	}
	switch c.Oversize {
	case OversizeFail, OversizeMetadataOnly:
	default:
		return fmt.Errorf("llmpkgscan: invalid oversize %q (want fail|metadata-only)", c.Oversize)
	}
	if c.MaliciousThreshold <= 0 || c.MaliciousThreshold > 1 {
		return fmt.Errorf("llmpkgscan: maliciousThreshold must be within (0,1], got %g", c.MaliciousThreshold)
	}
	if c.SuspiciousThreshold <= 0 || c.SuspiciousThreshold > 1 {
		return fmt.Errorf("llmpkgscan: suspiciousThreshold must be within (0,1], got %g", c.SuspiciousThreshold)
	}
	if c.Timeout < 0 {
		return errors.New("llmpkgscan: timeout must not be negative")
	}
	if err := c.Limits.validate(); err != nil {
		return err
	}
	if c.Budget.GlobalCeilingUSD < 0 || c.Budget.TenantCeilingUSD < 0 || c.Budget.Window < 0 {
		return errors.New("llmpkgscan: budget values must not be negative")
	}
	for tenant, v := range c.Budget.TenantCeilingsUSD {
		if v < 0 {
			return fmt.Errorf("llmpkgscan: budget ceiling for tenant %q must not be negative", tenant)
		}
	}
	if c.CacheTTL < 0 || c.ErrorTTL < 0 {
		return errors.New("llmpkgscan: cache TTLs must not be negative")
	}
	if c.MaxConcurrent < 1 {
		return errors.New("llmpkgscan: maxConcurrent must be at least 1")
	}
	return nil
}

// ecosystemAllowed reports whether the gate scans an ecosystem.
func (c Config) ecosystemAllowed(eco string) bool {
	ce := CanonEcosystem(eco)
	if ce == "" {
		return false
	}
	for _, e := range c.Exclude {
		if e == ce {
			return false
		}
	}
	for _, e := range c.Include {
		if e == ce {
			return true
		}
	}
	return false
}
