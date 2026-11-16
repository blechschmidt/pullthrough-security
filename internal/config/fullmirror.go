package config

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
)

// FullMirrorConfig configures the full-mirror engine (Task 189): what the
// upstreams that enable upstreams.<name>.fullMirror share — where the
// engine's state lives and who it fetches as. The engine follows each such
// upstream's registry and fetches every new file through the gated serve
// pipeline, as a client pull would, before any client asks for it.
type FullMirrorConfig struct {
	// StateDir holds the engine's state: per upstream the feed's cursor, the
	// batch being worked on, the counters, the byte budget spent, recent
	// errors, and the operators' pause and resync requests. Defaults to
	// "<cache.dir>/fullmirror" for the filesystem cache; required otherwise.
	// In a multi-replica deployment it must be a directory every replica
	// mounts: whichever replica leads continues from it.
	StateDir string `yaml:"stateDir"`
	// Tenant is the tenant the mirror fetches as (default: the default
	// tenant). Tenant-scoped gate policies, cache namespacing and the rate
	// limiter's per-tenant policy apply to it as to that tenant's clients.
	Tenant string `yaml:"tenant"`
	// Roles are the access-control roles (auth.roles) the mirror holds. With
	// auth enabled they are required: a file from an upstream no role grants
	// is refused, as a client's pull would be.
	Roles []string `yaml:"roles"`
}

// UpstreamFullMirrorConfig is an upstream's fullMirror block: whether the
// engine follows the upstream's registry, and what it fetches from it.
type UpstreamFullMirrorConfig struct {
	// Enabled has the engine follow the registry. Refused for an upstream
	// type nothing can follow yet — docs/full-mirroring.md lists, per type,
	// whether a feed adapter exists.
	Enabled bool `yaml:"enabled"`
	// Include and Exclude are RE2 patterns matched against the whole package
	// name: a package is mirrored when it matches an include pattern (or none
	// is given) and no exclude pattern.
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
	// Versions is the version policy: "all" (default) mirrors every version
	// a change concerns; "latest" mirrors the newest `latest` versions of
	// each package (by the ecosystem's version order; yanked versions never
	// count, pre-releases only for a package without a stable version).
	Versions string `yaml:"versions"`
	Latest   int    `yaml:"latest"`
	// MaxArtifactBytes refuses a file larger than this (0: no limit). A size
	// the registry states is checked before the fetch; otherwise the fetch is
	// cut off at the limit and nothing is cached.
	MaxArtifactBytes int64 `yaml:"maxArtifactBytes"`
	// ByteBudget is the most bytes the mirror adds to the cache from this
	// upstream, in total. Required: once it is spent the mirror waits, its
	// queue intact, for a larger budget.
	ByteBudget int64 `yaml:"byteBudget"`
	// Concurrency is how many packages are worked on at a time (default 2, at
	// most 32).
	Concurrency int `yaml:"concurrency"`
	// RequestsPerSecond paces every request made to the upstream on the
	// mirror's behalf — feed polls, version lists, file fetches (default 2).
	// The upstream's Retry-After holds all of them.
	RequestsPerSecond float64 `yaml:"requestsPerSecond"`
	// PollInterval is the time between two polls of a feed that has nothing
	// more to give (default 5m, at least 10s).
	PollInterval time.Duration `yaml:"pollInterval"`
	// OffPeak restricts the mirror to a daily window. Unset, it works around
	// the clock.
	OffPeak FullMirrorWindowConfig `yaml:"offPeak"`
	// DryRun polls the feed and applies every policy and the cache check, but
	// fetches nothing: what would be fetched is counted as skipped (dry-run).
	DryRun bool `yaml:"dryRun"`
	// Feed holds the feed adapter's options. "url" names the change feed
	// when the adapter cannot derive it from the upstream's URL (a private
	// registry's replication endpoint, a Git index): for the public
	// registries it is known. Other keys are type-specific (pip "mode",
	// julia "flavor", conan "binaries", homebrew "platforms", the Git-backed
	// feeds' "branch"); an unknown key is refused. docs/full-mirroring.md
	// lists them per type.
	Feed map[string]string `yaml:"feed"`
	// FullScan keeps every artifact of this upstream in the cache under a
	// current verdict of the LLM package-content scan gate (Task 192): the
	// mirror's fetches are judged as they arrive, what was cached before by a
	// backfill sweep. It needs llmPackageScan.enabled and fullScan.budget, and
	// works without enabled too: the cache of an upstream that is not mirrored
	// is scanned all the same.
	FullScan bool `yaml:"fullScan"`
}

// FullMirrorWindowConfig is a daily window: "HH:MM" bounds in an IANA time
// zone (default UTC). The window may wrap midnight (start 22:00, end 06:00).
type FullMirrorWindowConfig struct {
	Start    string `yaml:"start"`
	End      string `yaml:"end"`
	Timezone string `yaml:"timezone"`
}

// FullMirrorStateDir returns the full-mirror engine's state directory: the
// configured one, or "<cache.dir>/fullmirror" for the filesystem cache.
func (c *Config) FullMirrorStateDir() string {
	if d := strings.TrimSpace(c.FullMirror.StateDir); d != "" {
		return d
	}
	if c.Cache.Backend == "filesystem" && strings.TrimSpace(c.Cache.Dir) != "" {
		return filepath.Join(c.Cache.Dir, "fullmirror")
	}
	return ""
}

// FullMirrorUpstreams returns the names of the enabled upstreams that enable
// full mirroring, sorted.
func (c *Config) FullMirrorUpstreams() []string {
	var out []string
	for name, up := range c.Upstreams {
		if up.FullMirror != nil && up.FullMirror.Enabled && up.IsEnabled() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// maxRequestsPerSecond bounds requestsPerSecond.
const maxRequestsPerSecond = 10000

// validateFullMirror checks the full-mirror configuration: every fullMirror
// block's syntax, and for an enabled one that its type can be followed, that
// it has a budget, and that the engine has a durable home and an identity.
func (c *Config) validateFullMirror() error {
	names := make([]string, 0, len(c.Upstreams))
	for name := range c.Upstreams {
		names = append(names, name)
	}
	sort.Strings(names)
	anyEnabled := false
	for _, name := range names {
		up := c.Upstreams[name]
		fm := up.FullMirror
		if fm == nil {
			continue
		}
		where := fmt.Sprintf("config: upstream %q: fullMirror", name)
		if _, err := fullmirror.CompilePatterns(fm.Include); err != nil {
			return fmt.Errorf("%s.include: %w", where, err)
		}
		if _, err := fullmirror.CompilePatterns(fm.Exclude); err != nil {
			return fmt.Errorf("%s.exclude: %w", where, err)
		}
		if _, err := fullmirror.ParseVersionPolicy(fm.Versions, fm.Latest); err != nil {
			return fmt.Errorf("%s.versions: %w", where, err)
		}
		if fm.MaxArtifactBytes < 0 {
			return fmt.Errorf("%s.maxArtifactBytes must not be negative", where)
		}
		if fm.ByteBudget < 0 {
			return fmt.Errorf("%s.byteBudget must not be negative", where)
		}
		if fm.Concurrency < 0 || fm.Concurrency > fullmirror.MaxConcurrency {
			return fmt.Errorf("%s.concurrency must be between 0 (the default, %d) and %d", where, fullmirror.DefaultConcurrency, fullmirror.MaxConcurrency)
		}
		if fm.RequestsPerSecond < 0 || math.IsNaN(fm.RequestsPerSecond) || math.IsInf(fm.RequestsPerSecond, 0) || fm.RequestsPerSecond > maxRequestsPerSecond {
			return fmt.Errorf("%s.requestsPerSecond must be between 0 (the default, %g) and %d", where, fullmirror.DefaultRequestsPerSecond, maxRequestsPerSecond)
		}
		if fm.PollInterval != 0 && fm.PollInterval < fullmirror.MinPollInterval {
			return fmt.Errorf("%s.pollInterval must be at least %s (or unset: %s)", where, fullmirror.MinPollInterval, fullmirror.DefaultPollInterval)
		}
		if _, err := fullmirror.ParseWindow(fm.OffPeak.Start, fm.OffPeak.End, fm.OffPeak.Timezone); err != nil {
			return fmt.Errorf("%s.offPeak: %w", where, err)
		}
		if !fm.Enabled {
			continue
		}
		// The catalog's tier, and whether a feed adapter follows it.
		if err := fullmirror.Followable(up.Type); err != nil {
			return fmt.Errorf("%s.enabled: %w", where, err)
		}
		// The adapter's reading of the upstream and its options: a feed it
		// cannot locate, or an option it does not know, is refused now.
		if err := fullmirror.Check(fullmirror.Env{
			Upstream: name, Type: up.Type, URL: up.URL, Settings: up.Settings, Options: fm.Feed,
		}); err != nil {
			return fmt.Errorf("%s.feed: %w", where, err)
		}
		if fm.ByteBudget == 0 {
			return fmt.Errorf("%s.byteBudget is required: the most bytes the mirror may add to the cache from this upstream", where)
		}
		if fm.MaxArtifactBytes > fm.ByteBudget {
			return fmt.Errorf("%s.maxArtifactBytes (%d) is larger than the byteBudget (%d)", where, fm.MaxArtifactBytes, fm.ByteBudget)
		}
		anyEnabled = true
	}
	fc := c.FullMirror
	definedRole := map[string]bool{}
	for _, role := range c.Auth.Roles {
		definedRole[strings.TrimSpace(role.Name)] = true
	}
	for _, role := range fc.Roles {
		if strings.TrimSpace(role) == "" {
			return fmt.Errorf("config: fullMirror.roles has an empty role")
		}
		if c.Auth.Enabled && !definedRole[strings.TrimSpace(role)] {
			return fmt.Errorf("config: fullMirror.roles references undefined role %q (auth.roles)", role)
		}
	}
	if strings.ContainsAny(fc.Tenant, "\x00\r\n/") {
		return fmt.Errorf("config: fullMirror.tenant %q is not a tenant name", fc.Tenant)
	}
	if !anyEnabled {
		return nil
	}
	if c.FullMirrorStateDir() == "" {
		return fmt.Errorf("config: fullMirror.stateDir is required unless the cache is a filesystem cache (it then defaults to <cache.dir>/fullmirror)")
	}
	if c.Cache.Backend == "memory" {
		return fmt.Errorf("config: full mirroring needs a durable cache (filesystem or s3): the in-memory cache forgets what the mirror fetched while the cursor says it was fetched")
	}
	if c.Auth.Enabled && len(fc.Roles) == 0 {
		return fmt.Errorf("config: auth is enabled, and the full mirror needs roles to fetch with: set fullMirror.roles to roles (auth.roles) that grant the mirrored upstreams")
	}
	return nil
}
