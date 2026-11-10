package config

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/secrets"
	"gopkg.in/yaml.v3"
)

// Severity classifies a configuration validation issue.
type Severity string

const (
	// SeverityError marks a problem that prevents the configuration from being
	// loaded (the proxy would refuse to start). Errors fail a preflight check.
	SeverityError Severity = "error"
	// SeverityWarning marks a suspicious-but-loadable configuration: a likely
	// misconfiguration (a gate enabled without its dependency, a no-op setting)
	// that an operator should review. Warnings do not fail a preflight check.
	SeverityWarning Severity = "warning"
)

// Issue is a single validation finding, anchored to a dotted config field path
// (e.g. "license.enabled") so an operator can jump straight to the offending
// setting. Path is empty for whole-document problems (a YAML syntax error).
type Issue struct {
	Path     string   `json:"path,omitempty"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

// Report is the aggregated result of a validation pass: every issue found, with
// running counts and (when validating a concrete loaded config) the effective
// fingerprint. It is the single payload shared by the CLI subcommand and the
// admin preflight endpoint.
type Report struct {
	OK          bool    `json:"ok"`
	Errors      int     `json:"errors"`
	Warnings    int     `json:"warnings"`
	Issues      []Issue `json:"issues"`
	Fingerprint string  `json:"fingerprint,omitempty"`
}

// errorf records an error-severity issue.
func (r *Report) errorf(path, format string, args ...any) {
	r.Issues = append(r.Issues, Issue{Path: path, Message: fmt.Sprintf(format, args...), Severity: SeverityError})
}

// warnf records a warning-severity issue.
func (r *Report) warnf(path, format string, args ...any) {
	r.Issues = append(r.Issues, Issue{Path: path, Message: fmt.Sprintf(format, args...), Severity: SeverityWarning})
}

// finalize sorts issues deterministically (errors first, then by path/message),
// de-duplicates identical findings, and recomputes the summary counters. It is
// called exactly once at the end of every pass so the report is stable and
// suitable for golden tests and machine consumption.
func (r *Report) finalize() {
	seen := make(map[string]struct{}, len(r.Issues))
	deduped := r.Issues[:0]
	for _, is := range r.Issues {
		key := string(is.Severity) + "\x00" + is.Path + "\x00" + is.Message
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, is)
	}
	r.Issues = deduped

	sort.SliceStable(r.Issues, func(i, j int) bool {
		a, b := r.Issues[i], r.Issues[j]
		// Errors sort before warnings.
		if a.Severity != b.Severity {
			return a.Severity == SeverityError
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Message < b.Message
	})

	r.Errors, r.Warnings = 0, 0
	for _, is := range r.Issues {
		switch is.Severity {
		case SeverityError:
			r.Errors++
		case SeverityWarning:
			r.Warnings++
		}
	}
	r.OK = r.Errors == 0
	if r.Issues == nil {
		r.Issues = []Issue{}
	}
}

// Check validates an already-loaded, effective configuration. It runs the
// inter-subsystem consistency checks (a gate enabled without the backend,
// credentials, or peer subsystem it depends on) and folds in the authoritative
// schema/range/enum validation performed by Validate, surfacing the result as a
// single report. The effective fingerprint is attached so the caller can compare
// it against the running configuration's drift hash.
func (c *Config) Check() *Report {
	r := &Report{}
	c.checkInto(r)
	r.Fingerprint = Fingerprint(c)
	r.finalize()
	return r
}

// checkInto appends every finding for c to r without sorting/finalizing, so it
// can be shared by Check (a concrete config) and the candidate-file path that
// also collects unknown-key issues from the strict decoder.
func (c *Config) checkInto(r *Report) {
	c.checkConsistency(r)

	// Fold in the authoritative schema/type/range/enum validation. Validate is
	// fail-fast (it returns the first such error), so a candidate may need a
	// second pass once that one is fixed; the consistency and unknown-key checks
	// above/below are exhaustive in a single pass. The wording is normalized by
	// stripping the package's "config: " prefix.
	if err := c.Validate(); err != nil {
		msg := strings.TrimPrefix(err.Error(), "config: ")
		r.Issues = append(r.Issues, Issue{Message: msg, Severity: SeverityError})
	}
}

// checkConsistency holds the cross-field and inter-subsystem invariants: a
// subsystem that is enabled but whose required peer subsystem, backend, or
// credential is absent, plus settings that are silently no-ops. These are the
// problems a per-field schema check cannot see, and every one is reported (the
// pass never short-circuits) so an operator fixes them all at once.
func (c *Config) checkConsistency(r *Report) {
	// A proxy with no upstreams can cache nothing and serve nothing useful.
	if len(c.Upstreams) == 0 {
		r.warnf("upstreams", "no upstreams are configured; the proxy will not serve any package ecosystem")
	}

	// Encrypted (enc:v1:) values require a master key, or the proxy cannot
	// decrypt them at startup. Surface this at preflight rather than as a startup
	// crash, since candidate validation skips decryption.
	if c.hasEncryptedSecret() && !c.hasSecretsKey() {
		r.errorf("secrets", "configuration contains enc:v1: encrypted values but no master key is configured (set secrets.keyFile, secrets.passphrase, or the secrets.keyEnv environment variable)")
	}

	// License compliance reuses the SBOM the vulnerability subsystem generates,
	// and is off by default — so this only fires on a deliberate, inconsistent
	// operator choice (enabling license without the SBOM source it needs).
	if c.License.Enabled && !c.Vulnerabilities.Enabled {
		r.warnf("license.enabled", "license compliance reuses the SBOM produced by the vulnerability subsystem; enable vulnerabilities.enabled so licenses can be evaluated")
	}

	// LLM commit scanning needs credentials to reach the provider.
	if c.Scanning.Enabled && strings.TrimSpace(c.Scanning.APIKey) == "" {
		switch c.Scanning.Provider {
		case "claude", "codex":
			r.warnf("scanning.apiKey", "scanning is enabled with provider %q but no apiKey is configured; commit scanning will fail to authenticate to the LLM provider", c.Scanning.Provider)
		}
	}

	// Tracing enabled without an exporter endpoint is the documented inert state,
	// but worth flagging so an operator who meant to export spans notices.
	if c.Tracing.Enabled && strings.TrimSpace(c.Tracing.Endpoint) == "" {
		r.warnf("tracing.endpoint", "tracing is enabled but no OTLP endpoint is configured; spans are sampled but never exported")
	}

	// OTLP log export enabled without an endpoint is the documented inert state,
	// but worth flagging so an operator who meant to ship logs notices.
	if c.Telemetry.OTLPLogs.Enabled && strings.TrimSpace(c.Telemetry.OTLPLogs.Endpoint) == "" {
		r.warnf("telemetry.otlpLogs.endpoint", "OTLP log export is enabled but no endpoint is configured; operational logs are written to stderr but never exported")
	}

	// On a shared S3 cache, per-replica LRU eviction fights the object-store
	// lifecycle policy; the docs recommend leaving maxSizeBytes at 0.
	if c.Cache.Backend == "s3" && c.Cache.MaxSizeBytes > 0 {
		r.warnf("cache.maxSizeBytes", "cache.maxSizeBytes drives per-replica LRU eviction, which is unsafe on a shared S3 cache; leave it at 0 and manage retention with an object-store lifecycle policy")
	}

	// Metrics off but a subsystem only observable via metrics is on: surface the
	// blind spot rather than letting it pass silently.
	if c.Metering.Enabled && !c.Observability.Metrics {
		r.warnf("metering.enabled", "usage metering is enabled but observability.metrics is off; per-tenant usage gauges will not be exported")
	}

	// Peer cache federation (Task 143): flag the common misconfigurations so an
	// operator who turned it on notices before rollout.
	if c.CacheFed.Enabled {
		if len(c.CacheFed.Peers) == 0 {
			r.warnf("cacheFed.peers", "cache federation is enabled but no peers are configured; a local miss will always fall through to the upstream")
		}
		if strings.TrimSpace(c.CacheFed.Auth.SecretRef) == "" {
			if c.CacheFed.ServeOrDefault() {
				r.warnf("cacheFed.auth.secretRef", "cache federation is enabled with serving on but no auth secret is configured; the peer endpoint fails closed (serves nothing) and peer requests are unauthenticated")
			} else {
				r.warnf("cacheFed.auth.secretRef", "cache federation is enabled but no auth secret is configured; peer requests will carry no credential and siblings requiring auth will reject them")
			}
		}
		if !c.CacheFed.RequireDigestOrDefault() {
			r.warnf("cacheFed.requireDigest", "cacheFed.requireDigest is disabled; peer responses are verified only against the peer-advertised digest (transit integrity), which does not defend against a malicious peer")
		}
	}

	// Profiling is served under the admin API, so it is inert without it. Also
	// nudge operators to guard the surface: an unauthenticated admin API means
	// unauthenticated pprof, which leaks runtime internals and allows a
	// CPU-profile DoS.
	if c.Observability.Profiling {
		if !c.Observability.Admin {
			r.warnf("observability.profiling", "profiling is enabled but observability.admin is off; the pprof/trace endpoints are only mounted on the admin surface and will not be reachable")
		} else if !c.AdminAuth.Enabled && strings.TrimSpace(c.Observability.AdminToken) == "" {
			r.warnf("observability.profiling", "profiling is enabled on an unauthenticated admin surface; set adminAuth or observability.adminToken so the pprof/trace endpoints are not world-readable")
		}
	}
}

// hasSecretsKey reports whether a master encryption key is resolvable from the
// Secrets configuration or its environment variable.
func (c *Config) hasSecretsKey() bool {
	if strings.TrimSpace(c.Secrets.KeyFile) != "" || strings.TrimSpace(c.Secrets.Passphrase) != "" {
		return true
	}
	keyEnv := c.Secrets.KeyEnv
	if keyEnv == "" {
		keyEnv = "PTS_SECRETS_KEY"
	}
	return strings.TrimSpace(os.Getenv(keyEnv)) != ""
}

// hasEncryptedSecret reports whether any secret-bearing field carries the
// enc:v1: prefix. It mirrors the field set decryptSecrets resolves.
func (c *Config) hasEncryptedSecret() bool {
	candidates := []string{
		c.Scanning.APIKey,
		c.Provenance.GitHubToken,
		c.Observability.AdminToken,
		c.AdminAuth.SessionKey,
		c.AdminAuth.OIDC.ClientSecret,
		c.Audit.HMACKey,
		c.Audit.Transparency.SigningKey,
		c.Attest.SigningKey,
		c.Backup.Passphrase,
		c.Cache.S3.AccessKeyID,
		c.Cache.S3.SecretAccessKey,
		c.Cache.S3.SessionToken,
		c.Coordination.S3.AccessKeyID,
		c.Coordination.S3.SecretAccessKey,
		c.Coordination.S3.SessionToken,
	}
	for _, up := range c.Upstreams {
		candidates = append(candidates, up.Credentials.Username, up.Credentials.Password, up.Credentials.Token)
		for _, m := range up.Mirrors {
			candidates = append(candidates, m.Credentials.Username, m.Credentials.Password, m.Credentials.Token)
		}
	}
	for _, v := range candidates {
		if secrets.IsEncrypted(v) {
			return true
		}
	}
	return false
}

// CheckBytes validates a candidate configuration document supplied as raw YAML
// bytes — the form used by `ptctl config validate` and the admin preflight
// endpoint before a config is rolled out. It surfaces, in a single pass: every
// unknown/typo'd key and type mismatch (from a strict decode), every
// inter-subsystem consistency problem, and the first schema/range error.
//
// Decryption is intentionally skipped: a candidate is validated for structure
// and logic without requiring the production master key, so it can be checked
// from a workstation. enc:v1: values are still flagged when no key is in scope.
func CheckBytes(data []byte) *Report {
	r := &Report{}

	// Strict decode: collect ALL unknown-key and type-mismatch errors at once.
	collectStrictIssues(data, r)

	// Lenient decode for the logical checks. A syntax error here is terminal —
	// there is nothing further to check — so report it and stop.
	cfg, err := decodeLenient(data)
	if err != nil {
		r.Issues = append(r.Issues, Issue{Message: strings.TrimPrefix(err.Error(), "config: "), Severity: SeverityError})
		r.finalize()
		return r
	}

	cfg.checkInto(r)
	r.Fingerprint = Fingerprint(cfg)
	r.finalize()
	return r
}

// CheckFile is CheckBytes over a file on disk.
func CheckFile(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %q: %w", path, err)
	}
	return CheckBytes(data), nil
}

// decodeLenient layers a candidate document over the defaults without rejecting
// unknown keys (those are reported separately by collectStrictIssues) and
// without decrypting secrets, then applies ${ENV} expansion and PTS_* overrides
// so the logical checks see the same effective values the proxy would.
func decodeLenient(data []byte) (*Config, error) {
	cfg := Default()
	if len(strings.TrimSpace(string(data))) > 0 {
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("parsing config: %w", err)
		}
	}
	expandSecrets(&cfg)
	applyEnvOverrides(&cfg)
	return &cfg, nil
}

// collectStrictIssues decodes data with KnownFields(true) and records every
// resulting unknown-field / type-mismatch error as an Issue. yaml.v3 aggregates
// these into a *yaml.TypeError, so the whole document's typos are surfaced in
// one pass rather than one error at a time.
func collectStrictIssues(data []byte, r *Report) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	err := dec.Decode(&cfg)
	if err == nil {
		return
	}
	if te, ok := err.(*yaml.TypeError); ok {
		for _, e := range te.Errors {
			r.Issues = append(r.Issues, Issue{Message: e, Severity: SeverityError})
		}
		return
	}
	// A non-TypeError here is a YAML syntax error; decodeLenient reports it.
}
