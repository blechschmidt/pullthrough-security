// Package presets ships a library of vetted, versioned baseline security
// configurations ("compliance policy presets") that map a standard's controls
// onto concrete settings across the proxy's admission gates. An operator can
// preview (dry-run diff) and one-click apply a preset instead of hand-assembling
// dozens of gate settings.
//
// Each preset is a self-contained bundle: a control→gate-setting mapping table
// (the []Setting list) plus the compliance-scorecard controls it satisfies. The
// mapping is the single source of truth for three things: the dry-run differ
// (diff.go), the on-disk apply (manager.go), and the traceability matrix
// documented in docs/compliance-presets.md.
//
// The setting values are deliberately expressed as plain Go scalars/slices and
// dotted YAML paths (not typed config setters) so the same table drives both an
// in-memory projection onto *config.Config (for the differ, validation, and the
// simreplay what-if) and a surgical patch of the raw on-disk YAML (for apply),
// the latter preserving comments, encrypted secrets, and unrelated settings.
package presets

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// Compliance-scorecard control identifiers (see internal/compliance controlDefs).
// Presets reference these so the scorecard can attribute coverage to an applied
// preset. They are duplicated here as constants rather than imported to keep the
// dependency one-directional (compliance must never import presets).
const (
	ControlSignatureVerification = "signature-verification"
	ControlProvenanceAssociation = "provenance-association"
	ControlVulnerabilityGate     = "vulnerability-gate"
	ControlLicenseCompliance     = "license-compliance"
	ControlSecretFree            = "secret-free"
	ControlAirGapSealed          = "air-gap-sealed"
	ControlAuditTransparency     = "audit-transparency"
)

// Setting is one concrete gate setting a preset asserts: a dotted YAML path into
// the proxy configuration, the value to set there, a human description, the
// standard clause it implements (for the traceability matrix), and the
// compliance-scorecard controls it contributes to.
type Setting struct {
	// Path is the dotted YAML path into the configuration document, e.g.
	// "sigverify.requireSignature" or "license.deny". It is both the apply target
	// and the stable key in the traceability matrix.
	Path string `json:"path"`
	// Value is the value the preset sets at Path. Supported kinds: bool, string,
	// int, float64, and []string (rendered as a YAML sequence).
	Value any `json:"value"`
	// Desc explains, in operator terms, what the setting does.
	Desc string `json:"desc"`
	// Clause is the standard's control/clause identifier this setting implements,
	// e.g. "SLSA Build L3: provenance" or "NIST SSDF PW.4".
	Clause string `json:"clause,omitempty"`
	// Controls lists the compliance-scorecard control IDs this setting helps
	// satisfy (see the Control* constants).
	Controls []string `json:"controls,omitempty"`
}

// Preset is a named, versioned compliance baseline.
type Preset struct {
	// Name is the stable identifier used on the CLI and admin API (kebab-case).
	Name string `json:"name"`
	// Title is the human-readable name.
	Title string `json:"title"`
	// Description summarises the posture the preset establishes.
	Description string `json:"description"`
	// Version is the preset bundle version, bumped when its settings change so an
	// audit record pins exactly which baseline was applied.
	Version string `json:"version"`
	// Standard names the external framework the preset maps (for display/docs).
	Standard string `json:"standard"`
	// Settings is the control→gate-setting mapping table.
	Settings []Setting `json:"settings"`
}

// Controls returns the de-duplicated, sorted union of compliance-scorecard
// control IDs the preset's settings satisfy. The compliance scorecard uses this
// to attribute coverage to an applied preset.
func (p Preset) Controls() []string {
	seen := map[string]struct{}{}
	for _, s := range p.Settings {
		for _, c := range s.Controls {
			seen[c] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Summary is the compact descriptor returned by listing endpoints.
type Summary struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Standard    string   `json:"standard"`
	Settings    int      `json:"settings"`
	Controls    []string `json:"controls"`
}

// Summary projects the preset to its compact descriptor.
func (p Preset) Summary() Summary {
	return Summary{
		Name:        p.Name,
		Title:       p.Title,
		Description: p.Description,
		Version:     p.Version,
		Standard:    p.Standard,
		Settings:    len(p.Settings),
		Controls:    p.Controls(),
	}
}

// Candidate builds a simreplay candidate configuration that mirrors the preset's
// policy-as-code and risk-scoring posture. It lets the dry-run differ reuse the
// simreplay what-if machinery to show the preset's blast radius against captured
// traffic (admit↔block flips, band shifts, new violations) — see Simulate.
func (p Preset) Candidate() simreplay.CandidateConfig {
	includeDefault := true
	pol := &simreplay.PolicyCandidate{
		Enabled:              boolSetting(p, "policyEngine.enabled", true),
		Mode:                 stringSetting(p, "policyEngine.mode", "enforce"),
		DefaultAction:        stringSetting(p, "policyEngine.defaultAction", ""),
		IncludeDefaultBundle: &includeDefault,
	}
	risk := &simreplay.RiskCandidate{
		Enabled:         boolSetting(p, "riskScore.enabled", true),
		ThresholdBand:   stringSetting(p, "riskScore.thresholdBand", "high"),
		ThresholdAction: stringSetting(p, "riskScore.thresholdAction", "block"),
	}
	return simreplay.CandidateConfig{PolicyEngine: pol, RiskScore: risk}
}

// boolSetting returns the preset's value for path as a bool, or def if absent.
func boolSetting(p Preset, path string, def bool) bool {
	if v, ok := p.value(path); ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

// stringSetting returns the preset's value for path as a string, or def if absent.
func stringSetting(p Preset, path, def string) string {
	if v, ok := p.value(path); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func (p Preset) value(path string) (any, bool) {
	for _, s := range p.Settings {
		if s.Path == path {
			return s.Value, true
		}
	}
	return nil, false
}

// registry holds the embedded, vetted preset definitions keyed by Name.
var registry = func() map[string]Preset {
	m := map[string]Preset{}
	for _, p := range []Preset{slsaL3(), nistSSDF(), baselineHardened()} {
		m[p.Name] = p
	}
	return m
}()

// Names returns the registered preset names in a stable (sorted) order.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// All returns every registered preset in stable name order.
func All() []Preset {
	out := make([]Preset, 0, len(registry))
	for _, n := range Names() {
		out = append(out, registry[n])
	}
	return out
}

// List returns the compact summaries of every registered preset.
func List() []Summary {
	all := All()
	out := make([]Summary, 0, len(all))
	for _, p := range all {
		out = append(out, p.Summary())
	}
	return out
}

// Get returns the named preset. The error names the available presets so a typo
// is actionable.
func Get(name string) (Preset, error) {
	p, ok := registry[strings.TrimSpace(name)]
	if !ok {
		return Preset{}, fmt.Errorf("presets: unknown preset %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	return p, nil
}
