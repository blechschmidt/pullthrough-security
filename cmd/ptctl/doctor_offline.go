package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

// runDoctorOffline runs the statically-computable subset of the diagnostic
// against a config file, with no running proxy. It performs the checks that do
// not require live state — configuration validation (Task 85), secrets-provider
// resolution (Task 133), and gate-enablement coverage — and records the live-only
// checks as skipped so the report shape stays consistent with online mode.
func runDoctorOffline(path string, timeout time.Duration) *doctorReport {
	report := &doctorReport{
		Mode:        "offline",
		Target:      path,
		GeneratedAt: time.Now().UTC(),
	}

	// Validate the file first. CheckFile produces the exact same report the admin
	// preflight endpoint returns, including strict unknown-key detection.
	rep, ferr := config.CheckFile(path)
	validate := checkResult{Name: "configuration validity", Category: "config"}
	if ferr != nil {
		validate.Severity = sevError
		validate.Summary = "config file could not be read/parsed"
		validate.Details = []string{firstLine(ferr.Error())}
		validate.Remediation = "fix the YAML syntax / path before deploying"
		report.add(validate)
	} else {
		for _, is := range cappedIssues(toConfigIssues(rep.Issues), 8) {
			loc := is.Path
			if loc == "" {
				loc = "(document)"
			}
			validate.Details = append(validate.Details, fmt.Sprintf("[%s] %s: %s", is.Severity, loc, is.Message))
		}
		switch {
		case rep.Errors > 0:
			validate.Severity = sevError
			validate.Summary = fmt.Sprintf("%d error(s), %d warning(s)", rep.Errors, rep.Warnings)
			validate.Remediation = "fix the fields above before deploying this config"
		case rep.Warnings > 0:
			validate.Severity = sevWarn
			validate.Summary = fmt.Sprintf("%d warning(s)", rep.Warnings)
			validate.Remediation = "review the flagged settings; they are loadable but likely misconfigured"
		default:
			validate.Severity = sevOK
			validate.Summary = "valid, no issues"
		}
		report.add(validate)
	}

	// Load the effective config for the remaining static checks. If it fails to
	// load (a hard validation error), the remaining checks cannot run.
	cfg, lerr := config.Load(path)
	if lerr != nil {
		report.add(checkResult{
			Name: "secrets-provider resolution", Category: "config", Severity: sevSkip,
			Summary: "config did not load; cannot resolve secrets",
		})
		report.add(checkResult{
			Name: "gate-enablement coverage", Category: "policy", Severity: sevSkip,
			Summary: "config did not load; cannot assess gate coverage",
		})
	} else {
		report.add(offlineSecretsCheck(cfg, timeout))
		report.add(offlineGateCoverageCheck(cfg))
	}

	// Live-only checks: recorded as skipped so CI sees the same check set in both
	// modes and an operator knows exactly what offline mode did not cover.
	for _, lc := range []struct{ name, cat string }{
		{"proxy reachability", "connectivity"},
		{"configuration drift", "config"},
		{"upstream reachability", "connectivity"},
		{"keys & certificate expiry", "crypto"},
		{"cache integrity", "cache"},
		{"leader election", "coordination"},
		{"kill-switch / lockdown", "incident"},
	} {
		report.add(checkResult{
			Name: lc.name, Category: lc.cat, Severity: sevSkip,
			Summary: "requires a running proxy (online mode)",
		})
	}
	return report
}

// offlineSecretsCheck actively re-resolves every secretRef-bearing credential in
// the loaded config against the configured providers (env/file/vault/literal),
// reusing the proxy's own resolution path. Errors name the offending field, never
// its value.
func offlineSecretsCheck(cfg *config.Config, timeout time.Duration) checkResult {
	res := checkResult{Name: "secrets-provider resolution", Category: "config"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resolver, err := config.NewSecretsResolver(cfg, logger)
	if err != nil {
		res.Severity = sevError
		res.Summary = "secrets provider could not be initialized"
		res.Details = []string{firstLine(err.Error())}
		res.Remediation = "check the secrets.* provider configuration (Vault address/auth, file paths)"
		return res
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Resolve against a copy so the loaded config is left untouched.
	clone := *cfg
	if err := config.ResolveRefs(ctx, &clone, resolver); err != nil {
		res.Severity = sevError
		res.Summary = "a secret reference failed to resolve"
		res.Details = []string{firstLine(err.Error())}
		res.Remediation = "ensure the referenced env var / file / Vault path exists and is readable"
		return res
	}
	res.Severity = sevOK
	res.Summary = "all secret references resolve"
	return res
}

// offlineGateCoverageCheck assesses, statically from the config, which admission
// gates are enabled and which ecosystems the enabled upstreams span — flagging a
// deployment that fronts packages with no security gating at all.
func offlineGateCoverageCheck(cfg *config.Config) checkResult {
	res := checkResult{Name: "gate-enablement coverage", Category: "policy"}

	ecos := map[string]struct{}{}
	for _, u := range cfg.Upstreams {
		if u.IsEnabled() && strings.TrimSpace(u.Type) != "" {
			ecos[ecosystemLabel(strings.ToLower(u.Type))] = struct{}{}
		}
	}

	// The full set of pull-path admission gates, read directly from the config.
	gates := []struct {
		name    string
		enabled bool
	}{
		{"commit-scan", cfg.Scanning.Enabled},
		{"vuln", cfg.Vulnerabilities.Enabled},
		{"license", cfg.License.Enabled},
		{"sigverify", cfg.Sigverify.Enabled},
		{"provenance", cfg.Provenance.Enabled},
		{"buildprov", cfg.BuildProv.Enabled},
		{"nameguard", cfg.Nameguard.Enabled},
		{"malfeed", cfg.Malfeed.Enabled},
		{"maturity", cfg.Maturity.Enabled},
		{"continuity", cfg.Continuity.Enabled},
		{"depfirewall", cfg.DepFirewall.Enabled},
		{"installhooks", cfg.InstallHooks.Enabled},
		{"mlguard", cfg.MLGuard.Enabled},
		{"avscan", cfg.AVScan.Enabled},
		{"contentscan", cfg.ContentScan.Enabled},
		{"llmpkgscan", cfg.LLMPackageScan.Enabled},
	}
	var enabled []string
	for _, g := range gates {
		if g.enabled {
			enabled = append(enabled, g.name)
		}
	}

	res.Details = append(res.Details, "ecosystems: "+joinSorted(ecos))
	res.Details = append(res.Details, fmt.Sprintf("gates enabled (%d): %s", len(enabled), orNone(strings.Join(enabled, ", "))))

	switch {
	case len(ecos) > 0 && len(enabled) == 0:
		res.Severity = sevWarn
		res.Summary = "no admission gates enabled"
		res.Remediation = "artifacts would be proxied without security gating; enable at least vulnerability scanning"
	case !cfg.Vulnerabilities.Enabled:
		res.Severity = sevWarn
		res.Summary = fmt.Sprintf("%d gate(s) enabled; vulnerability scanning off", len(enabled))
		res.Remediation = "enable vulnerabilities.enabled for baseline supply-chain coverage"
	default:
		res.Severity = sevOK
		res.Summary = fmt.Sprintf("%d gate(s) enabled across %d ecosystem(s)", len(enabled), len(ecos))
	}
	return res
}

// toConfigIssues adapts the internal config.Issue slice to the ptctl-local
// configIssue shape used by the shared rendering helpers.
func toConfigIssues(in []config.Issue) []configIssue {
	out := make([]configIssue, 0, len(in))
	for _, is := range in {
		out = append(out, configIssue{Path: is.Path, Message: is.Message, Severity: string(is.Severity)})
	}
	return out
}

// ecosystemLabel normalizes a backend type string to a canonical ecosystem label,
// folding the known aliases (deb/apt, rpm/yum, pypi/pip, oci/docker, pub/dart) so
// the coverage summary does not double-count equivalent backends.
func ecosystemLabel(t string) string {
	switch t {
	case "deb", "apt":
		return "apt"
	case "rpm", "yum":
		return "yum"
	case "pypi", "pip":
		return "pip"
	case "oci", "docker":
		return "docker"
	case "pub", "dart":
		return "dart"
	case "huggingface", "hf":
		return "huggingface"
	default:
		return t
	}
}
