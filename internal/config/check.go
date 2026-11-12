package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/clientip"
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

	c.checkLLMPackageScan(r)
	c.checkTrustedProxies(r)
	c.checkUserLinks(r)

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

// checkUserLinks reports the personal-links configurations (Task 177) that load
// but do not do what an operator who wrote them would expect.
func (c *Config) checkUserLinks(r *Report) {
	u := c.UserLinks
	if !u.Enabled {
		return
	}
	// Nobody can sign in, so nobody gets a link unless an administrator issues it.
	if !u.OIDC.Enabled {
		r.warnf("userLinks.oidc.enabled", "personal links are enabled without an identity provider; users cannot sign in, and links exist only when an administrator issues them (ptctl userlinks issue)")
	}
	// With access control on, a user without a role may pull nothing.
	if c.Auth.Enabled && len(u.DefaultRoles) == 0 && len(u.RoleMap) == 0 {
		r.warnf("userLinks.defaultRoles", "auth.enabled is on but signed-in users are given no role (userLinks.defaultRoles and userLinks.roleMap are empty); a personal link will authenticate its user and then be refused by RBAC unless the identity provider's groups carry the names of roles in auth.roles")
	}
	// A link is a credential in a URL; over plain HTTP it travels in the clear —
	// unless it does not travel at all: a proxy reached on loopback (a test
	// set-up, a sidecar) is not on a network.
	if pub, err := url.Parse(strings.TrimSpace(c.Server.PublicURL)); err == nil && strings.EqualFold(pub.Scheme, "http") && !isLoopbackHost(pub.Hostname()) {
		r.warnf("server.publicUrl", "personal links are enabled on a plain-HTTP public URL; a link is a credential and would cross the network unencrypted — serve the proxy over HTTPS (and note that the sign-in cookies need userLinks.insecureCookies over HTTP)")
	}
	// A registry in memory forgets every link at restart, and is not shared.
	backend := u.StoreBackend(c.Cache.Backend)
	if backend == "memory" {
		r.warnf("userLinks.store.backend", "the personal-link registry is kept in memory: every link stops working when the proxy restarts, and a link created on one replica is unknown to the others")
	}
	// Several replicas, each with a directory of its own, each know only the
	// links they created themselves.
	if backend == "filesystem" && c.Coordination.Enabled && !strings.EqualFold(strings.TrimSpace(c.Coordination.Mode), "memory") {
		r.warnf("userLinks.store", "this looks like a multi-replica deployment (coordination is enabled) with the personal-link registry in a directory; every replica must mount the same directory (userLinks.store.dir on a shared volume) or use the s3 store, or a link works only on the replica that created it")
	}
	// Links that never expire are bounded by revocation alone.
	if u.LinkTTL == 0 {
		r.warnf("userLinks.linkTtl", "personal links do not expire (linkTtl is 0s); a link that leaked keeps working until someone revokes it")
	}
}

// isLoopbackHost reports whether a URL's host names this machine itself.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkLLMPackageScan reports the LLM package-content scan gate's loadable-but-
// questionable configurations (Task 173): the ones a schema check cannot see
// and an operator would want to hear about before the first pull stalls or the
// first invoice arrives.
func (c *Config) checkLLMPackageScan(r *Report) {
	if !c.LLMPackageScan.Enabled {
		return
	}
	l := c.EffectiveLLMPackageScan()

	// No credential: every scan fails, and under fail-open that is silent.
	if llmPackageScanProviders[l.Provider] && strings.TrimSpace(l.APIKey) == "" {
		r.warnf("llmPackageScan.apiKey", "the LLM package scan is enabled with provider %q but no apiKey is configured (and none is inherited from scanning.apiKey); every scan will fail to authenticate unless the provider's own environment variable supplies a key", l.Provider)
	}
	// Spend is driven by what clients pull; without a ceiling it is unbounded.
	if !l.Budget.Enabled || (l.Budget.GlobalCeilingUSD == 0 && l.Budget.TenantCeilingUSD == 0 && len(l.Budget.TenantCeilingsUSD) == 0) {
		r.warnf("llmPackageScan.budget", "the LLM package scan has no cost ceiling; every first pull of an artifact is a paid scan, so set llmPackageScan.budget (enabled plus a global and/or per-tenant ceiling)")
	}
	// Verdicts in memory are re-bought after every restart.
	if strings.TrimSpace(l.StoreDir) == "" {
		r.warnf("llmPackageScan.storeDir", "llmPackageScan.storeDir is empty, so verdicts are kept in memory only; every artifact is scanned (and paid for) again after a restart")
	}
	// The client waits for the verdict before the first byte; the server must
	// not give up on the response first.
	if c.Server.WriteTimeout > 0 && l.Timeout > 0 && l.Timeout >= c.Server.WriteTimeout {
		r.warnf("llmPackageScan.timeout", "llmPackageScan.timeout (%s) is not below server.writeTimeout (%s); a scan that runs to its limit would have its response cut off", l.Timeout, c.Server.WriteTimeout)
	}
	// An enforcing action that fails open stops enforcing whenever the provider
	// is unreachable or the budget is spent — and whenever a package makes itself
	// unscannable. Worth a deliberate decision rather than a default.
	if strings.EqualFold(strings.TrimSpace(l.FailMode), "open") || strings.TrimSpace(l.FailMode) == "" {
		switch strings.ToLower(strings.TrimSpace(l.Action)) {
		case "", "block", "quarantine":
			r.warnf("llmPackageScan.failMode", "llmPackageScan.action enforces verdicts but failMode is \"open\": an artifact that cannot be scanned (provider outage, exhausted budget, oversized or unparseable package) is served anyway; use failMode \"closed\" where that is not acceptable")
		}
	}
	// A scan sends package contents to the LLM provider. An upstream that needs
	// credentials is, as a rule, a private registry — the one place whose packages
	// an operator may not want to leave the network. Name each such upstream so
	// that sending its packages is a decision rather than a default.
	scanned := func(upType string) bool {
		eco := canonLLMEcosystem(upType)
		for _, e := range l.Exclude {
			if canonLLMEcosystem(e) == eco {
				return false
			}
		}
		include := l.Include
		if len(include) == 0 {
			include = llmPackageScanDefaultEcosystems
		}
		for _, e := range include {
			if canonLLMEcosystem(e) == eco {
				return true
			}
		}
		return false
	}
	// A git upstream reaches this gate through its LFS objects only.
	upstreamScanned := func(up UpstreamConfig) bool {
		if canonLLMEcosystem(up.Type) == "git" {
			return c.Git.LFS.Enabled && scanned(llmEcosystemGitLFS)
		}
		return scanned(up.Type)
	}
	excluded := map[string]bool{}
	for _, name := range l.ExcludeUpstreams {
		excluded[strings.TrimSpace(name)] = true
	}
	private := make([]string, 0, 2)
	for name, up := range c.Upstreams {
		cr := up.Credentials
		if !up.IsEnabled() || excluded[name] || !upstreamScanned(up) {
			continue
		}
		if cr.Username != "" || cr.Password != "" || cr.Token != "" {
			private = append(private, name)
		}
	}
	sort.Strings(private)
	for _, name := range private {
		r.warnf("llmPackageScan.excludeUpstreams", "upstream %q is authenticated (likely a private registry) and its packages will be sent to the LLM provider for scanning; add it to llmPackageScan.excludeUpstreams if its contents must not leave your network", name)
	}
	// An ecosystem named for scanning that no upstream serves is a typo or a
	// leftover.
	if len(l.Include) > 0 {
		served := map[string]bool{}
		for _, up := range c.Upstreams {
			if !up.IsEnabled() {
				continue
			}
			eco := canonLLMEcosystem(up.Type)
			if eco == "git" {
				// A git upstream serves this gate's "git-lfs" ecosystem, and only
				// with LFS proxying on.
				if c.Git.LFS.Enabled {
					served[llmEcosystemGitLFS] = true
				}
				continue
			}
			served[eco] = true
		}
		for _, e := range l.Include {
			ce := canonLLMEcosystem(e)
			if ce == "git" {
				continue // reported below, with what to do instead
			}
			if !served[ce] {
				if ce == llmEcosystemGitLFS {
					r.warnf("llmPackageScan.include", "llmPackageScan.include names %q but no enabled git upstream proxies Git LFS (git.lfs.enabled); no LFS object will be scanned", e)
					continue
				}
				r.warnf("llmPackageScan.include", "llmPackageScan.include names ecosystem %q but no enabled upstream has that type; nothing will be scanned for it", e)
			}
		}
	}
	// "git" is a valid upstream type but not something this gate reads: a clone
	// or fetch is commits, which are the LLM commit scan's to read. Naming it here
	// suggests an expectation the gate does not meet.
	for _, list := range []struct {
		name string
		ecos []string
	}{{"include", l.Include}, {"exclude", l.Exclude}} {
		for _, e := range list.ecos {
			if canonLLMEcosystem(e) == "git" {
				r.warnf("llmPackageScan."+list.name, "llmPackageScan.%s names %q, which this gate never scans: the commits of a Git clone or fetch are the LLM commit scan's (scanning.*), not this gate's. Use \"git-lfs\" to scope the scan of Git LFS objects", list.name, e)
			}
		}
	}
	// An oversized artifact under the default "fail" handling is an unscanned
	// artifact, and under fail-open it is served. Images and model repositories
	// are where artifacts above the limit are the rule rather than the exception.
	if strings.TrimSpace(l.Oversize) == "" || strings.EqualFold(strings.TrimSpace(l.Oversize), "fail") {
		large := make([]string, 0, 2)
		for name, up := range c.Upstreams {
			if !up.IsEnabled() || excluded[name] || !upstreamScanned(up) {
				continue
			}
			switch canonLLMEcosystem(up.Type) {
			case "docker", "huggingface", "nix", "homebrew":
				large = append(large, name)
			}
		}
		sort.Strings(large)
		if len(large) > 0 {
			r.warnf("llmPackageScan.oversize", "llmPackageScan.oversize is \"fail\" and upstream(s) %s serve artifacts that are routinely larger than limits.maxArtifactBytes (image layers, model weights, binary archives): each such artifact gets no verdict and failMode decides. Set oversize \"metadata-only\" to have the inventory, scripts and image config judged instead, or raise the limit", strings.Join(large, ", "))
		}
	}
}

// canonLLMEcosystem folds the ecosystem aliases the LLM package-scan gate
// accepts onto upstream type names.
func canonLLMEcosystem(e string) string {
	switch e = strings.ToLower(strings.TrimSpace(e)); e {
	case "deb":
		return "apt"
	case "rpm":
		return "yum"
	case "pub":
		return "dart"
	case "oci":
		return "docker"
	case "lfs", "gitlfs":
		return llmEcosystemGitLFS
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
		c.LLMPackageScan.APIKey,
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
		c.UserLinks.SessionKey,
		c.UserLinks.OIDC.ClientSecret,
		c.UserLinks.Store.S3.AccessKeyID,
		c.UserLinks.Store.S3.SecretAccessKey,
		c.UserLinks.Store.S3.SessionToken,
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

// checkTrustedProxies flags a server.trustedProxies entry that trusts every
// address. Such an entry makes X-Forwarded-For authoritative from any peer, so
// any client can attribute its downloads — in the download log and the audit
// log — to an address of its choosing. It is loadable (a lab behind a NAT may
// want it), hence a warning rather than an error.
func (c *Config) checkTrustedProxies(r *Report) {
	for i, entry := range c.Server.TrustedProxies {
		prefix, err := clientip.ParsePrefix(entry)
		if err != nil {
			continue // reported as an error by Validate
		}
		if prefix.Bits() == 0 {
			r.warnf(fmt.Sprintf("server.trustedProxies[%d]", i),
				"%q trusts every peer: any client can then forge its address with an X-Forwarded-For header, and the download log and audit log will record the forged one; list only your load balancers or ingress controllers", entry)
		}
	}
}
