package config

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FullScanConfig configures the full scan (Task 192): every artifact in the
// cache of an upstream whose fullMirror block sets fullScan — or, with
// enabled, of every upstream the LLM package scan covers — is kept under a
// current verdict of the LLM package-content scan gate (llmPackageScan). The
// full mirror's fetches are judged as they arrive; what was cached before is
// put before the gate by a backfill sweep. A malicious verdict follows the
// gate's action ladder before any client asks for the artifact. See
// docs/full-mirroring.md#full-scan.
type FullScanConfig struct {
	// Enabled extends the full scan to every cached artifact of every upstream
	// the LLM package scan covers (llmPackageScan.include / exclude /
	// excludeUpstreams), not only those of the upstreams whose fullMirror
	// block sets fullScan.
	Enabled bool `yaml:"enabled"`
	// Concurrency is how many of the full scan's scans run at a time (default
	// 2, at most 32). It is held below llmPackageScan.maxConcurrent, and the
	// full scan starts a scan only while no client's scan waits for a slot:
	// the scans client pulls start always come first.
	Concurrency int `yaml:"concurrency"`
	// Budget caps what the full scan's model calls cost. At least one ceiling
	// is required; once one is spent the queue pauses until its window rolls
	// over or the ceiling is raised.
	Budget FullScanBudgetConfig `yaml:"budget"`
	// SweepInterval is the time between two backfill sweeps of the cache
	// (default 6h, at least 1m). A sweep also runs when a replica comes to lead.
	SweepInterval time.Duration `yaml:"sweepInterval"`
	// MaxArtifacts bounds the artifacts the full scan tracks (default
	// 1000000); beyond it an artifact is still judged when a client pulls it.
	MaxArtifacts int `yaml:"maxArtifacts"`
}

// FullScanBudgetConfig is the full scan's cost budget, in US dollars, per UTC
// calendar day and month (0: no ceiling for that window).
type FullScanBudgetConfig struct {
	DailyUSD   float64 `yaml:"dailyUsd"`
	MonthlyUSD float64 `yaml:"monthlyUsd"`
}

// FullScanRequested reports whether any full scan is configured: the global
// one, or an enabled upstream's fullMirror.fullScan.
func (c *Config) FullScanRequested() bool {
	return c.FullScan.Enabled || len(c.FullScanUpstreams()) > 0
}

// FullScanUpstreams returns the enabled upstreams whose fullMirror block sets
// fullScan, sorted. (With fullScan.enabled every upstream the LLM package scan
// covers is in scope as well; the server works that out with the gate.)
func (c *Config) FullScanUpstreams() []string {
	var out []string
	for name, up := range c.Upstreams {
		if up.FullMirror != nil && up.FullMirror.FullScan && up.IsEnabled() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// FullScanStateDir is the full scan's state directory: "fullscan" inside the
// full mirror's state directory.
func (c *Config) FullScanStateDir() string {
	if d := c.FullMirrorStateDir(); d != "" {
		return filepath.Join(d, "fullscan")
	}
	return ""
}

// Bounds of the full scan's settings.
const (
	maxFullScanConcurrency = 32
	minFullScanSweep       = time.Minute
)

// validateFullScan checks the full scan's configuration.
func (c *Config) validateFullScan() error {
	fs := c.FullScan
	where := "config: fullScan"
	switch {
	case fs.Concurrency < 0 || fs.Concurrency > maxFullScanConcurrency:
		return fmt.Errorf("%s.concurrency must be between 0 (the default, 2) and %d", where, maxFullScanConcurrency)
	case fs.SweepInterval != 0 && fs.SweepInterval < minFullScanSweep:
		return fmt.Errorf("%s.sweepInterval must be at least %s (or unset: 6h)", where, minFullScanSweep)
	case fs.MaxArtifacts < 0:
		return fmt.Errorf("%s.maxArtifacts must not be negative", where)
	}
	for _, v := range []struct {
		name string
		usd  float64
	}{{"dailyUsd", fs.Budget.DailyUSD}, {"monthlyUsd", fs.Budget.MonthlyUSD}} {
		if v.usd < 0 || math.IsNaN(v.usd) || math.IsInf(v.usd, 0) {
			return fmt.Errorf("%s.budget.%s must be a non-negative amount", where, v.name)
		}
	}
	if !c.FullScanRequested() {
		return nil
	}
	ups := c.FullScanUpstreams()
	why := "fullScan.enabled"
	if !fs.Enabled {
		why = "upstreams." + strings.Join(ups, ", upstreams.") + ".fullMirror.fullScan"
	}
	if !c.LLMPackageScan.Enabled {
		return fmt.Errorf("config: %s needs the LLM package-content scan gate: set llmPackageScan.enabled", why)
	}
	if c.LLMPackageScan.MaxConcurrent == 1 {
		return fmt.Errorf("config: %s needs llmPackageScan.maxConcurrent of at least 2 (or unset: 4): one scan slot is always left to client pulls", why)
	}
	if fs.Budget.DailyUSD == 0 && fs.Budget.MonthlyUSD == 0 {
		return fmt.Errorf("config: %s needs a cost budget: set fullScan.budget.dailyUsd or fullScan.budget.monthlyUsd (US dollars per UTC day or month)", why)
	}
	excluded := map[string]bool{}
	for _, u := range c.LLMPackageScan.ExcludeUpstreams {
		excluded[strings.TrimSpace(u)] = true
	}
	for _, name := range ups {
		if excluded[name] {
			return fmt.Errorf("config: upstream %q: fullMirror.fullScan is set, but llmPackageScan.excludeUpstreams excludes the upstream from the LLM package scan", name)
		}
	}
	if c.FullScanStateDir() == "" {
		return fmt.Errorf("config: %s needs a state directory: set fullMirror.stateDir (it defaults to <cache.dir>/fullmirror only for a filesystem cache)", why)
	}
	if c.Auth.Enabled && len(c.FullMirror.Roles) == 0 {
		return fmt.Errorf("config: auth is enabled, and the full scan needs roles to read the cache with: set fullMirror.roles to roles (auth.roles) that grant the scanned upstreams")
	}
	return nil
}
