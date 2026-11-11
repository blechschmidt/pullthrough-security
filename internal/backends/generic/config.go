package generic

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// BackendConfig is the declarative definition of a pull-through backend for an
// ecosystem that has no dedicated adapter (Task 147). It is attached to an
// upstream of type "generic" and lets an operator onboard a new source entirely
// in YAML — path classification, cacheability, verify-on-fetch content-address
// verification, metadata URL rewriting, and content-gate selection — with no
// code changes.
//
// It carries yaml tags so it can be embedded directly in the configuration
// schema (internal/config), which both drives the generated configuration
// reference and gives a single, authoritative Validate implementation shared by
// config preflight and backend construction.
type BackendConfig struct {
	// Routes are ordered path-classification rules evaluated against the inbound
	// request path (the path with the "/v1/<name>" mount prefix already stripped,
	// leading slash included). The first route whose Match matches the path decides
	// how the request is served. A request matching no route is rejected
	// (ErrNotSupported → 501), so the route set is an explicit allowlist of what
	// this upstream will proxy — an unmatched path can never become an open relay.
	// At least one route is required.
	Routes []RouteConfig `yaml:"routes"`
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is mounted (e.g. "https://proxy.example.com/v1/mysource"), used to rewrite
	// absolute upstream URLs embedded in metadata documents back through the proxy
	// so dependent downloads flow through the gated pipeline. Optional; when empty
	// the backend falls back to the root-relative "/v1/<name>" mount.
	PublicBaseURL string `yaml:"publicBaseURL"`
	// MaxRewriteBytes bounds a metadata document buffered for URL rewriting; a
	// document larger than this is streamed through unmodified. Optional; a
	// non-positive value selects the 32 MiB default. Must not be negative.
	MaxRewriteBytes int64 `yaml:"maxRewriteBytes"`
}

// RouteConfig is one ordered path-classification rule.
type RouteConfig struct {
	// Name labels the route in diagnostics, metrics, and the resolved metadata.
	// Optional; defaults to the route's ordinal position.
	Name string `yaml:"name"`
	// Match is an RE2 regular expression matched against the inbound request path
	// (leading slash included). Required and must compile. Anchor it (^…$) to keep
	// a route from matching more broadly than intended.
	Match string `yaml:"match"`
	// Cacheable reports whether responses for this route may be cached and
	// therefore routed through the full content-gate admission pipeline
	// (serveCacheable). Mutable listings/metadata must leave this false so they are
	// served live and revalidated. Default false.
	Cacheable bool `yaml:"cacheable"`
	// Rewrite, when true, buffers the response body and rewrites every absolute
	// upstream-base URL to the proxy's public base so nested artifact downloads
	// route back through the proxy (and its gates). It is for metadata/index
	// documents and is mutually exclusive with both Cacheable and Verify on the
	// same route (an immutable artifact is never rewritten). Because it declares
	// the route a metadata document, the LLM package-content scan skips what the
	// route serves, unless the route lists that gate in Gates. Default false.
	Rewrite bool `yaml:"rewrite"`
	// Verify, when set, enables verify-on-fetch content-address verification of the
	// artifact this route serves: the fetched bytes are streamed through a hasher
	// and a digest mismatch aborts the cache write and the client stream. It
	// requires Cacheable (verifying a non-cached resource is pointless churn).
	Verify *VerifyConfig `yaml:"verify"`
	// Gates is the operator's declared allowlist of content-gate identifiers that
	// apply to artifacts served by this route (e.g. "contentscan", "avscan"). Each
	// name must be a known gate. It is recorded in the artifact's resolved metadata
	// for audit and telemetry; the globally-enabled gates still run over every
	// cacheable artifact (a cacheable route is what subjects an artifact to the
	// content-gate pipeline), so this documents intent rather than disabling gates.
	//
	// One identifier does more than document intent. A route that lists
	// "llmpkgscan" (or "llmPackageScan") is classified as an installable payload
	// for the LLM package-content scan: what it serves is examined even when the
	// response is not an archive, and even when the route is not cacheable.
	//
	// "llmPackageScan" is that gate's configuration key, accepted here as an alias
	// of its identifier. The alias is recorded as "llmpkgscan", once, however the
	// route spelled it.
	Gates []string `yaml:"gates"`
	// MediaType overrides the Content-Type served for this route (e.g.
	// "application/gzip"). Optional; the upstream content type is used otherwise.
	MediaType string `yaml:"mediaType"`
}

// VerifyConfig declares how an artifact's expected content digest is recovered
// and which algorithm verifies it.
type VerifyConfig struct {
	// Algorithm is the digest algorithm: "sha256", "sha512", or "sha1". Required.
	// (sha1 is accepted for ecosystems that still publish it, but sha256+ is
	// strongly preferred.)
	Algorithm string `yaml:"algorithm"`
	// Source selects where the expected digest comes from:
	//
	//	"sidecar" — fetched from a sibling file whose URL is derived from the
	//	            artifact URL (SidecarSuffix). This is the common pattern for
	//	            registries that publish a ".sha256"/".sha512" next to each file.
	//	"path"    — captured from a group in the route Match regex (DigestGroup),
	//	            for content-addressed layouts that embed the digest in the URL.
	//
	// Default "sidecar".
	Source string `yaml:"source"`
	// SidecarSuffix forms the sidecar URL from the artifact URL, e.g. ".sha256".
	// Required when Source is "sidecar".
	SidecarSuffix string `yaml:"sidecarSuffix"`
	// SidecarReplacesExtension, when true, replaces the artifact URL's final path
	// extension with SidecarSuffix (foo-1.0.tar.gz → foo-1.0.sha256) instead of
	// appending it (foo-1.0.tar.gz → foo-1.0.tar.gz.sha256). Default append.
	SidecarReplacesExtension bool `yaml:"sidecarReplacesExtension"`
	// DigestGroup is the 1-based index of the capture group in the route Match
	// regex that holds the hex digest. Required (and ≥1) when Source is "path".
	DigestGroup int `yaml:"digestGroup"`
	// FailOpen, when true, serves the artifact unverified if no expected digest can
	// be recovered (e.g. a missing or malformed sidecar). Default false — a missing
	// digest fails closed and the fetch is refused, the safe default for a route an
	// operator has explicitly declared verified.
	FailOpen bool `yaml:"failOpen"`
}

// Digest verification sources.
const (
	sourceSidecar = "sidecar"
	sourcePath    = "path"
)

// knownAlgorithms is the set of digest algorithms the verifier supports.
var knownAlgorithms = map[string]bool{
	"sha256": true,
	"sha512": true,
	"sha1":   true,
}

// gateLLMPackageScan is the identifier of the LLM package-content scan gate. A
// route that lists it is classified as an installable payload (see
// RouteConfig.Gates).
const gateLLMPackageScan = "llmpkgscan"

// knownGates is the set of content-gate identifiers a route may reference in its
// Gates allowlist. They mirror the gate labels the proxy runs over a cacheable
// artifact in serveCacheable; referencing an unknown gate is a config error so a
// typo is caught at load time rather than silently ignored. A route may also
// spell a gate by one of the gateAliases.
var knownGates = map[string]bool{
	"vulnscan":     true,
	"license":      true,
	"sbomdiff":     true,
	"installhooks": true,
	"contentscan":  true,
	"mlguard":      true,
	"avscan":       true,
	"llmpkgscan":   true,
	"sigverify":    true,
	"malfeed":      true,
	"maturity":     true,
	"nameguard":    true,
	"depfirewall":  true,
	"reposcore":    true,
}

// gateAliases maps an alternative spelling a route may use for a gate to the
// gate's canonical identifier. The LLM package-content scan is configured under
// the "llmPackageScan" key, so an operator who has just written that section
// names the gate the same way in a route; both spellings mean the one gate.
// Aliases are accepted by Validate and stored under the canonical identifier
// (canonicalGates); they are not identifiers in their own right, so KnownGates
// does not list them.
var gateAliases = map[string]string{
	"llmPackageScan": gateLLMPackageScan,
}

// canonicalGate returns the canonical identifier of a gate a route names, and
// whether the name is a known gate or an alias of one. Names are case-sensitive.
func canonicalGate(name string) (string, bool) {
	if knownGates[name] {
		return name, true
	}
	if canonical, ok := gateAliases[name]; ok {
		return canonical, true
	}
	return "", false
}

// canonicalGates returns a route's gate list as canonical identifiers: every
// alias is replaced by the gate it names and a gate named more than once (under
// one spelling or several) is kept once, at its first position. A name
// canonicalGate does not know is dropped; Validate has rejected it before a
// route is compiled.
func canonicalGates(gates []string) []string {
	if len(gates) == 0 {
		return nil
	}
	out := make([]string, 0, len(gates))
	seen := make(map[string]bool, len(gates))
	for _, g := range gates {
		canonical, ok := canonicalGate(g)
		if !ok || seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	return out
}

// KnownGates returns the sorted set of valid content-gate identifiers, for
// documentation and error messages. It lists canonical identifiers only: the
// alternative spellings a route may also use (gateAliases) are not included.
func KnownGates() []string {
	out := make([]string, 0, len(knownGates))
	for g := range knownGates {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// Validate checks the declarative configuration for structural soundness and
// rejects unsafe or incoherent routes before a backend is built — the load-time
// gate the task requires. It is called both by configuration preflight
// (internal/config) and by New (defense in depth). name is the upstream name,
// used only for diagnostics. A nil receiver is an error (a generic upstream must
// carry a generic block).
func (c *BackendConfig) Validate(name string) error {
	if c == nil {
		return fmt.Errorf("generic %q: a 'generic' configuration block is required for type \"generic\"", name)
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("generic %q: at least one route is required", name)
	}
	if c.MaxRewriteBytes < 0 {
		return fmt.Errorf("generic %q: maxRewriteBytes must not be negative", name)
	}
	seenNames := make(map[string]bool, len(c.Routes))
	for i := range c.Routes {
		r := &c.Routes[i]
		label := r.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i)
		}
		if r.Name != "" {
			if seenNames[r.Name] {
				return fmt.Errorf("generic %q route %s: duplicate route name %q", name, label, r.Name)
			}
			seenNames[r.Name] = true
		}
		if strings.TrimSpace(r.Match) == "" {
			return fmt.Errorf("generic %q route %s: match is required", name, label)
		}
		re, err := regexp.Compile(r.Match)
		if err != nil {
			return fmt.Errorf("generic %q route %s: invalid match regexp %q: %w", name, label, r.Match, err)
		}
		if r.Rewrite && r.Cacheable {
			return fmt.Errorf("generic %q route %s: rewrite and cacheable are mutually exclusive (an immutable artifact is never rewritten)", name, label)
		}
		if r.Rewrite && r.Verify != nil {
			return fmt.Errorf("generic %q route %s: rewrite and verify are mutually exclusive", name, label)
		}
		for _, g := range r.Gates {
			if _, ok := canonicalGate(g); !ok {
				return fmt.Errorf("generic %q route %s: unknown content gate %q (known: %s)", name, label, g, strings.Join(KnownGates(), ", "))
			}
		}
		if r.Verify != nil {
			if err := r.Verify.validate(name, label, re); err != nil {
				return err
			}
		}
	}
	return nil
}

// validate checks a single route's verification rule against the compiled Match
// regex (so a "path" source's DigestGroup can be range-checked).
func (v *VerifyConfig) validate(name, label string, match *regexp.Regexp) error {
	algo := strings.ToLower(strings.TrimSpace(v.Algorithm))
	if algo == "" {
		return fmt.Errorf("generic %q route %s: verify.algorithm is required", name, label)
	}
	if !knownAlgorithms[algo] {
		return fmt.Errorf("generic %q route %s: unsupported verify.algorithm %q (supported: sha256, sha512, sha1)", name, label, v.Algorithm)
	}
	source := strings.ToLower(strings.TrimSpace(v.Source))
	if source == "" {
		source = sourceSidecar
	}
	switch source {
	case sourceSidecar:
		if strings.TrimSpace(v.SidecarSuffix) == "" {
			return fmt.Errorf("generic %q route %s: verify.sidecarSuffix is required when verify.source is %q", name, label, sourceSidecar)
		}
	case sourcePath:
		if v.DigestGroup < 1 {
			return fmt.Errorf("generic %q route %s: verify.digestGroup must be >= 1 when verify.source is %q", name, label, sourcePath)
		}
		if v.DigestGroup > match.NumSubexp() {
			return fmt.Errorf("generic %q route %s: verify.digestGroup %d exceeds the %d capture group(s) in the match regexp", name, label, v.DigestGroup, match.NumSubexp())
		}
	default:
		return fmt.Errorf("generic %q route %s: unknown verify.source %q (supported: sidecar, path)", name, label, v.Source)
	}
	return nil
}
