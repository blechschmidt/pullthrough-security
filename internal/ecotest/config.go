package ecotest

import (
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// RunConfig is everything needed to render the proxy configuration for one
// ecosystem run. Every value is concrete (paths, addresses, commit hashes), so
// the rendered file is exactly what an operator would write by hand.
type RunConfig struct {
	// Ecosystem is the ecosystem under test.
	Ecosystem Ecosystem
	// ListenAddr is the proxy's listen address ("127.0.0.1:41234").
	ListenAddr string
	// PublicURL is the base URL clients reach the proxy at.
	PublicURL string
	// StateDir is the directory holding all of the proxy's on-disk state for the
	// run (cache, commit mirrors, cursors, verdicts, provenance links).
	StateDir string
	// TLSCertFile and TLSKeyFile enable HTTPS termination when both are set.
	TLSCertFile string
	TLSKeyFile  string
	// LLMProvider is "claude" or "openai"; LLMBaseURL is the mock's base URL for
	// that provider.
	LLMProvider string
	LLMBaseURL  string
	// SourceRepo is the fixture source repository the commit scanner watches.
	SourceRepo string
	// BenignCommit and MaliciousCommit are the fixture commits the good and the
	// bad package are pinned to.
	BenignCommit    string
	MaliciousCommit string
	// Intercept, when set, enables TLS interception (Task 172): the forward
	// proxy and the NAT listeners.
	Intercept *InterceptListeners
}

// InterceptListeners are the interception listeners of a run.
type InterceptListeners struct {
	// ForwardAddr is the forward proxy's listen address (HTTPS_PROXY).
	ForwardAddr string
	// NATHTTPSAddr and NATHTTPAddr receive the connections the network sends
	// to the proxy for the upstream hosts (ports 443 and 80).
	NATHTTPSAddr string
	NATHTTPAddr  string
	// CADir holds the interception CA the proxy generates on first start.
	CADir string
}

// InterceptCACertPath is where the proxy of a run writes its interception CA.
func InterceptCACertPath(caDir string) string { return filepath.Join(caDir, "intercept-ca.crt") }

// AuditLogPath is where the proxy of a run writes its audit log.
func AuditLogPath(stateDir string) string { return filepath.Join(stateDir, "audit", "audit.log") }

// AdminToken guards the admin API of the proxy under test. The harness reads
// the proxy's state through that API, and issues the personal cache link of the
// personal-link check with it — which an admin surface without authentication
// refuses to do.
const AdminToken = "ecotest-admin-token"

// sourceRepoName is the name the fixture repository is watched under.
const sourceRepoName = "ecotest-source"

// RenderConfig renders the proxy configuration (YAML) for a run. The
// configuration is the production shape of "gate package pulls on the LLM scan
// of their source commit":
//
//   - the ecosystem's upstream, pointing at the real public registry;
//   - commit scanning with an LLM provider (the mock) and the continuous commit
//     scanner watching the source repository, history included;
//   - provenance with operator pins tying the good package to the benign commit
//     and the bad package to the malicious one;
//   - an admission policy that blocks any artifact whose source commit the
//     scanner flagged malicious, and admits unpinned packages (the transitive
//     dependencies a real install drags in).
func RenderConfig(rc RunConfig) ([]byte, error) {
	e := rc.Ecosystem
	if rc.ListenAddr == "" || rc.PublicURL == "" || rc.StateDir == "" {
		return nil, fmt.Errorf("ecotest: RenderConfig(%s): ListenAddr, PublicURL and StateDir are required", e.ID)
	}
	if (rc.TLSCertFile == "") != (rc.TLSKeyFile == "") {
		return nil, fmt.Errorf("ecotest: RenderConfig(%s): TLS needs both a certificate and a key", e.ID)
	}
	if e.TLS && rc.TLSCertFile == "" {
		return nil, fmt.Errorf("ecotest: RenderConfig(%s): the ecosystem requires TLS but no certificate was supplied", e.ID)
	}

	server := map[string]any{
		"httpAddr":  rc.ListenAddr,
		"publicUrl": rc.PublicURL,
	}
	if rc.TLSCertFile != "" {
		server["tlsCertFile"] = rc.TLSCertFile
		server["tlsKeyFile"] = rc.TLSKeyFile
	}
	if e.RegistryDefault != "" {
		server["registry"] = map[string]any{"defaultUpstream": e.RegistryDefault}
	}
	if ic := rc.Intercept; ic != nil {
		// TLS interception (Task 172), both ways in: the forward proxy for
		// clients given HTTPS_PROXY, the NAT listeners for clients given
		// nothing. The routing table is derived from the upstreams; the CA is
		// generated on first start.
		intercept := map[string]any{
			"enabled":    true,
			"listenAddr": ic.ForwardAddr,
			"nat":        map[string]any{"httpsAddr": ic.NATHTTPSAddr, "httpAddr": ic.NATHTTPAddr},
			"caCertFile": InterceptCACertPath(ic.CADir),
			"caKeyFile":  filepath.Join(ic.CADir, "intercept-ca.key"),
			"generateCa": true,
			// APT and DNF repositories are commonly configured with http://
			// URLs, which a forward proxy receives as absolute-form requests.
			"allowPlainHttp": true,
		}
		if len(e.InterceptHosts) > 0 {
			hosts := map[string]any{}
			for rule, upstream := range e.InterceptHosts {
				hosts[rule] = upstream
			}
			intercept["hosts"] = hosts
		}
		server["intercept"] = intercept
	}

	upstreams := map[string]any{}
	for _, u := range e.upstreams() {
		entry := map[string]any{"type": u.Type, "url": u.URL}
		if len(u.Settings) > 0 {
			settings := map[string]any{}
			for k, v := range u.Settings {
				settings[k] = v
			}
			entry["settings"] = settings
		}
		upstreams[u.Name] = entry
	}

	cfg := map[string]any{
		"server": server,
		// Debug-level JSON: one machine-readable record per request, which the
		// harness reads to assert on what the client actually requested.
		"logging":   map[string]any{"level": "debug", "format": "json"},
		"cache":     map[string]any{"backend": "filesystem", "dir": filepath.Join(rc.StateDir, "cache")},
		"upstreams": upstreams,
		// The admin API is how the harness observes the proxy (cache entries,
		// scan verdicts, provenance links); metrics carry the counters it asserts.
		"observability": map[string]any{"metrics": true, "admin": true, "adminToken": AdminToken},
		// Personal cache links (Task 177): every package source is also served
		// under a path prefix that names a user. There is no identity provider
		// here; the link the suite uses is issued by the operator, through the
		// admin API (`ptctl userlinks issue`).
		"userLinks": map[string]any{
			"enabled": true,
			"store":   map[string]any{"backend": "filesystem", "dir": filepath.Join(rc.StateDir, "userlinks")},
		},
		// The tamper-evident audit log is the authoritative record of every
		// admission decision; the harness reads the block it expects from there.
		"audit": map[string]any{
			"enabled": true,
			"file":    AuditLogPath(rc.StateDir),
			"hmacKey": "ecotest-audit-hmac-key",
		},
	}

	// Git is the one ecosystem with no package coordinate to gate: it gets a
	// plain caching proxy. Every package ecosystem gets the full admission chain.
	if e.Bad != nil {
		if rc.LLMProvider == "" || rc.LLMBaseURL == "" || rc.SourceRepo == "" {
			return nil, fmt.Errorf("ecotest: RenderConfig(%s): LLMProvider, LLMBaseURL and SourceRepo are required", e.ID)
		}
		if rc.BenignCommit == "" || rc.MaliciousCommit == "" {
			return nil, fmt.Errorf("ecotest: RenderConfig(%s): both fixture commits are required", e.ID)
		}

		cfg["scanning"] = map[string]any{
			"enabled":  true,
			"provider": rc.LLMProvider,
			"baseUrl":  rc.LLMBaseURL,
			// The mock accepts any key; a real deployment sets ANTHROPIC_API_KEY /
			// OPENAI_API_KEY (or a secretRef) here.
			"apiKey": "ecotest-mock-key",
			"failOn": "high",
			"commit": map[string]any{
				"storeDir": filepath.Join(rc.StateDir, "verdicts"),
			},
			"watch": map[string]any{
				"enabled":   true,
				"mirrorDir": filepath.Join(rc.StateDir, "commit-mirrors"),
				"stateDir":  filepath.Join(rc.StateDir, "commit-cursors"),
				// Scan the repository's existing history on first sight, then poll.
				"backfill":     true,
				"pollInterval": "2s",
				"repos": []any{map[string]any{
					"name":     sourceRepoName,
					"url":      rc.SourceRepo,
					"branches": []any{"main"},
				}},
			},
		}

		pins := []any{
			pinEntry(e.Upstream.Type, e.Good, rc.SourceRepo, rc.BenignCommit),
			pinEntry(e.Upstream.Type, *e.Bad, rc.SourceRepo, rc.MaliciousCommit),
		}
		cfg["provenance"] = map[string]any{
			"enabled":  true,
			"storeDir": filepath.Join(rc.StateDir, "provenance"),
			"pins":     pins,
		}

		cfg["policy"] = map[string]any{
			"enabled": true,
			// A lookup error must not silently admit: this is a security gate.
			"failClosed": true,
			"default": map[string]any{
				"blockMalicious": true,
				// A real install pulls transitive dependencies nobody pinned; they
				// are admitted. Only a coordinate with a KNOWN-malicious source
				// commit is refused, so a block is attributable to the LLM verdict.
				"onMissingProvenance": "allow",
				"onMissingScan":       "allow",
			},
		}
	}

	// yaml.v3 emits map keys in sorted order, so the rendered file is byte-stable.
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("ecotest: rendering config for %s: %w", e.ID, err)
	}
	header := fmt.Sprintf("# Generated by internal/ecotest for the %q ecosystem run. Do not edit.\n", e.ID)
	return append([]byte(header), out...), nil
}

// pinEntry renders one provenance pin for a package.
func pinEntry(ecosystem string, p Package, repo, commit string) map[string]any {
	pin := map[string]any{
		"ecosystem":  ecosystem,
		"name":       p.pinName(),
		"repository": repo,
		"commit":     commit,
	}
	if p.CoordinateVersion != "" {
		pin["version"] = p.CoordinateVersion
	}
	return pin
}
