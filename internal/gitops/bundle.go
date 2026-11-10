// Package gitops implements continuous GitOps reconciliation of the proxy's
// policy/config bundles from a version-controlled source of truth (a Git
// repository, an OCI artifact, or — air-gap friendly — a local path / pre-fetched
// bundle).
//
// Enterprises manage policy-as-code in version control, not by editing the live
// configuration. This subsystem closes the loop: on a coord-guarded interval (so
// only the HA leader reconciles) it fetches the desired-state bundle, verifies its
// signature/digest against the proxy's existing trust model (the same Ed25519/
// ECDSA/RSA DSSE key conventions used by internal/audit and internal/attestbundle),
// runs it through the existing configcheck validation and the simreplay blast-radius
// what-if, and then either:
//
//   - applies it — surgically patching the on-disk config file (preserving
//     comments, encrypted secrets, and untouched settings), recording a full
//     Merkle-audited apply event with the source commit SHA and a before/after
//     diff; or
//   - in "suggest" mode, surfaces the pending change for human approval through
//     the dual-control approvals workflow, applying it only once granted.
//
// It detects and reports drift when the live configuration diverges from the Git
// source of truth, and supports rolling back to the last-known-good applied
// revision.
//
// The desired-state bundle is a small, declarative document: a list of dotted
// config paths and the values to set there. This is structurally identical to a
// compliance preset (internal/presets), so the heavy lifting — projecting settings
// onto the running config, validating the projection (configcheck), computing the
// before/after fingerprints and per-setting diff, surgically patching the on-disk
// YAML, and the simreplay blast-radius what-if — is reused verbatim by converting a
// Bundle into a presets.Preset.
package gitops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/pullthrough-security/internal/presets"
)

// BundleAPIVersion is the supported desired-state bundle schema identifier. A
// bundle that declares a different apiVersion is rejected so a future incompatible
// format cannot be silently mis-applied.
const BundleAPIVersion = "pullthrough.gitops/v1"

// Setting is one desired config setting the bundle asserts: a dotted YAML path
// into the proxy configuration and the value to set there. It mirrors
// presets.Setting (and supported value kinds: bool, string, int, float64, and
// []string).
type Setting struct {
	// Path is the dotted YAML path into the configuration document, e.g.
	// "policyEngine.mode" or "license.deny".
	Path string `json:"path" yaml:"path"`
	// Value is the value to set at Path. Supported kinds: bool, string, int,
	// float64, and []string (rendered as a YAML sequence).
	Value any `json:"value" yaml:"value"`
	// Desc optionally explains, in operator terms, what the setting does.
	Desc string `json:"desc,omitempty" yaml:"desc,omitempty"`
}

// Bundle is a parsed desired-state policy/config bundle: the set of config
// settings the source of truth asserts, plus optional metadata. It is the
// declarative unit GitOps reconciles toward.
type Bundle struct {
	// APIVersion pins the bundle schema; must equal BundleAPIVersion.
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	// Revision is an optional bundle-declared revision identifier. When the source
	// supplies its own revision (e.g. a Git commit SHA) that takes precedence.
	Revision string `json:"revision,omitempty" yaml:"revision,omitempty"`
	// Description summarises the posture the bundle establishes (for display).
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Settings is the desired config settings list.
	Settings []Setting `json:"settings" yaml:"settings"`
}

// ParseBundle decodes a desired-state bundle document (YAML, which is a superset
// of JSON). It validates the apiVersion and that at least one setting is present,
// so an empty or mistyped document cannot reconcile the live config to nothing.
func ParseBundle(raw []byte) (Bundle, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return Bundle{}, fmt.Errorf("gitops: bundle document is empty")
	}
	var b Bundle
	if err := yaml.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("gitops: parsing bundle: %w", err)
	}
	b.APIVersion = strings.TrimSpace(b.APIVersion)
	if b.APIVersion == "" {
		return Bundle{}, fmt.Errorf("gitops: bundle is missing apiVersion (expected %q)", BundleAPIVersion)
	}
	if b.APIVersion != BundleAPIVersion {
		return Bundle{}, fmt.Errorf("gitops: unsupported bundle apiVersion %q (expected %q)", b.APIVersion, BundleAPIVersion)
	}
	if len(b.Settings) == 0 {
		return Bundle{}, fmt.Errorf("gitops: bundle declares no settings (refusing to reconcile to an empty desired state)")
	}
	seen := map[string]struct{}{}
	for i, s := range b.Settings {
		p := strings.TrimSpace(s.Path)
		if p == "" {
			return Bundle{}, fmt.Errorf("gitops: bundle setting #%d has an empty path", i+1)
		}
		if _, dup := seen[p]; dup {
			return Bundle{}, fmt.Errorf("gitops: bundle sets path %q more than once", p)
		}
		seen[p] = struct{}{}
		b.Settings[i].Path = p
		// Normalise YAML-decoded scalar kinds to the kinds presets.valueNode accepts
		// (bool, string, int, float64, []string). yaml.v3 decodes ints as int and
		// untyped scalars as string already, but a sequence decodes as []any; coerce
		// homogeneous string sequences to []string.
		b.Settings[i].Value = normalizeValue(s.Value)
	}
	return b, nil
}

// normalizeValue coerces a yaml-decoded value into one of the kinds the presets
// patcher supports. Sequences of scalars become []string; everything else passes
// through (bool/int/float64/string). An unsupported kind is left as-is and will be
// rejected later by the presets value encoder, surfacing a clear error.
func normalizeValue(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprintf("%v", e))
		}
		return out
	case []string:
		return t
	default:
		return v
	}
}

// Preset converts the bundle into a presets.Preset so the reconciler can reuse the
// preset machinery (Diff, Project, PatchOnDisk, Simulate) verbatim. revision names
// the resulting synthetic preset version, pinning exactly which bundle a diff/apply
// corresponds to.
func (b Bundle) Preset(revision string) presets.Preset {
	settings := make([]presets.Setting, 0, len(b.Settings))
	for _, s := range b.Settings {
		settings = append(settings, presets.Setting{
			Path:  s.Path,
			Value: s.Value,
			Desc:  s.Desc,
		})
	}
	desc := b.Description
	if desc == "" {
		desc = "GitOps desired-state policy/config bundle"
	}
	return presets.Preset{
		Name:        "gitops",
		Title:       "GitOps desired state",
		Description: desc,
		Version:     revision,
		Standard:    "GitOps source of truth",
		Settings:    settings,
	}
}

// Paths returns the sorted dotted paths the bundle governs (for audit/diff display).
func (b Bundle) Paths() []string {
	out := make([]string, 0, len(b.Settings))
	for _, s := range b.Settings {
		out = append(out, s.Path)
	}
	sort.Strings(out)
	return out
}

// Digest returns the hex-encoded SHA-256 of raw bundle bytes, used both as a
// content identity (for idempotent reconciliation) and as the value an operator
// can pin in config to require an exact desired-state document.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
