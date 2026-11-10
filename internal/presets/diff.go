package presets

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// SettingDiff is the per-setting outcome of a dry-run diff: the configured value
// versus what the preset would set it to.
type SettingDiff struct {
	Path     string   `json:"path"`
	Desc     string   `json:"desc"`
	Clause   string   `json:"clause,omitempty"`
	Controls []string `json:"controls,omitempty"`
	Current  string   `json:"current"`
	Proposed string   `json:"proposed"`
	Changed  bool     `json:"changed"`
}

// Diff is the result of dry-running a preset against the running configuration:
// the per-setting deltas, a configcheck validation of the projected config, and
// the before/after effective fingerprints. It is what the CLI and admin preview
// render, and exactly what apply would change.
type Diff struct {
	Preset      string        `json:"preset"`
	Title       string        `json:"title"`
	Version     string        `json:"version"`
	Standard    string        `json:"standard"`
	GeneratedAt time.Time     `json:"generatedAt"`
	Settings    []SettingDiff `json:"settings"`
	Changed     int           `json:"changed"`
	Unchanged   int           `json:"unchanged"`
	// Controls is the union of compliance-scorecard control IDs the preset
	// satisfies — what the scorecard attributes to the applied preset.
	Controls []string `json:"controls"`
	// RunningFingerprint / ProposedFingerprint are the effective-config SHA-256
	// digests before and after projection (config.Fingerprint).
	RunningFingerprint  string `json:"runningFingerprint"`
	ProposedFingerprint string `json:"proposedFingerprint"`
	// Validation is the configcheck report for the projected configuration. A
	// preset that would produce an invalid config surfaces here so apply can be
	// refused.
	Validation *config.Report `json:"validation,omitempty"`
}

// Diff dry-runs the preset against the running configuration. It projects the
// preset onto a clone of running, computes per-setting deltas, validates the
// projected configuration (reusing configcheck), and records the before/after
// fingerprints.
func (p Preset) Diff(running *config.Config) (Diff, error) {
	if running == nil {
		return Diff{}, fmt.Errorf("presets: running configuration is nil")
	}
	d := Diff{
		Preset:             p.Name,
		Title:              p.Title,
		Version:            p.Version,
		Standard:           p.Standard,
		GeneratedAt:        time.Now().UTC(),
		Controls:           p.Controls(),
		RunningFingerprint: config.Fingerprint(running),
	}

	// Marshal the running config to a YAML node tree we can read current values
	// from and patch to produce the projection. Going through the config struct
	// ensures both current and proposed values render in the same canonical form
	// (e.g. durations as "72h0m0s"), so textual comparison is faithful.
	runningData, err := yaml.Marshal(running)
	if err != nil {
		return Diff{}, fmt.Errorf("presets: marshaling running config: %w", err)
	}
	patched, err := patchYAML(runningData, p.Settings)
	if err != nil {
		return Diff{}, err
	}
	projected, err := decodeConfig(patched)
	if err != nil {
		return Diff{}, fmt.Errorf("presets: decoding projected config: %w", err)
	}
	d.ProposedFingerprint = config.Fingerprint(projected)
	d.Validation = projected.Check()

	// Re-marshal both configs to nodes so per-setting reads share canonical form.
	runDoc, err := parseDoc(runningData)
	if err != nil {
		return Diff{}, err
	}
	projData, err := yaml.Marshal(projected)
	if err != nil {
		return Diff{}, fmt.Errorf("presets: marshaling projected config: %w", err)
	}
	projDoc, err := parseDoc(projData)
	if err != nil {
		return Diff{}, err
	}

	for _, s := range p.Settings {
		path := strings.Split(s.Path, ".")
		cur := renderNode(getNode(runDoc, path))
		prop := renderNode(getNode(projDoc, path))
		sd := SettingDiff{
			Path:     s.Path,
			Desc:     s.Desc,
			Clause:   s.Clause,
			Controls: s.Controls,
			Current:  cur,
			Proposed: prop,
			Changed:  cur != prop,
		}
		if sd.Changed {
			d.Changed++
		} else {
			d.Unchanged++
		}
		d.Settings = append(d.Settings, sd)
	}
	return d, nil
}

// Project returns a clone of running with the preset's settings applied. It is
// the in-memory projection the differ and the simreplay what-if build on.
func (p Preset) Project(running *config.Config) (*config.Config, error) {
	if running == nil {
		return nil, fmt.Errorf("presets: running configuration is nil")
	}
	data, err := yaml.Marshal(running)
	if err != nil {
		return nil, fmt.Errorf("presets: marshaling running config: %w", err)
	}
	patched, err := patchYAML(data, p.Settings)
	if err != nil {
		return nil, err
	}
	return decodeConfig(patched)
}

// PatchOnDisk surgically applies the preset's settings to a raw on-disk config
// document, preserving comments, encrypted secrets, key order, and every setting
// the preset does not touch. It is the byte transform that apply writes back.
// A nil/empty input yields a fresh document carrying only the preset's settings.
func (p Preset) PatchOnDisk(raw []byte) ([]byte, error) {
	return patchYAML(raw, p.Settings)
}

// Simulate reuses the simreplay what-if machinery to replay captured admission
// records through the preset's policy+risk posture, returning the blast radius
// (admit↔block flips, band shifts, new violations, per-tenant impact). The
// records carry their own baseline verdicts, so the diff is preset-vs-production.
func (p Preset) Simulate(records []simreplay.Record, opts simreplay.Options) (simreplay.DiffReport, error) {
	ev, cleanup, err := simreplay.BuildEvaluator(p.Candidate())
	if err != nil {
		return simreplay.DiffReport{}, fmt.Errorf("presets: building candidate evaluator: %w", err)
	}
	defer func() { _ = cleanup() }()
	return simreplay.Run(records, ev, opts), nil
}

// decodeConfig layers a (possibly partial) YAML document over the defaults,
// matching how the proxy loads configuration, so the projected config is the
// effective configuration the proxy would run.
func decodeConfig(data []byte) (*config.Config, error) {
	cfg := config.Default()
	if len(strings.TrimSpace(string(data))) > 0 {
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("presets: decoding config: %w", err)
		}
	}
	return &cfg, nil
}

// --- YAML node helpers -----------------------------------------------------

// patchYAML parses a YAML document and sets each setting's value at its dotted
// path, creating intermediate mappings as needed, then re-marshals. An empty
// input starts from an empty mapping.
func patchYAML(raw []byte, settings []Setting) ([]byte, error) {
	var doc yaml.Node
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("presets: parsing config document: %w", err)
		}
	}
	root := documentRoot(&doc)
	for _, s := range settings {
		valNode, err := valueNode(s.Value)
		if err != nil {
			return nil, fmt.Errorf("presets: setting %q: %w", s.Path, err)
		}
		if err := setNode(root, strings.Split(s.Path, "."), valNode); err != nil {
			return nil, fmt.Errorf("presets: setting %q: %w", s.Path, err)
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("presets: marshaling patched config: %w", err)
	}
	return out, nil
}

// documentRoot returns the mapping node at the document root, initialising the
// node tree (document → empty mapping) when the input was empty.
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
	}
	root := doc.Content[0]
	if root.Kind == 0 {
		root.Kind = yaml.MappingNode
	}
	return root
}

// parseDoc parses bytes into a document node (for read-only navigation).
func parseDoc(raw []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("presets: parsing config document: %w", err)
	}
	return &doc, nil
}

// setNode sets value at path within a mapping node, creating intermediate
// mapping nodes for missing keys. The final key's value node is replaced.
func setNode(mapping *yaml.Node, path []string, value *yaml.Node) error {
	if mapping.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping at %q", strings.Join(path, "."))
	}
	key := path[0]
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			if len(path) == 1 {
				mapping.Content[i+1] = value
				return nil
			}
			child := mapping.Content[i+1]
			if child.Kind != yaml.MappingNode {
				// Replace a non-mapping (or null) child with a fresh mapping so we can
				// descend.
				child = &yaml.Node{Kind: yaml.MappingNode}
				mapping.Content[i+1] = child
			}
			return setNode(child, path[1:], value)
		}
	}
	// Key not present: append it.
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	if len(path) == 1 {
		mapping.Content = append(mapping.Content, keyNode, value)
		return nil
	}
	child := &yaml.Node{Kind: yaml.MappingNode}
	mapping.Content = append(mapping.Content, keyNode, child)
	return setNode(child, path[1:], value)
}

// getNode navigates to the value node at path within a document/mapping, or nil
// when any segment is absent.
func getNode(doc *yaml.Node, path []string) *yaml.Node {
	node := doc
	if node != nil && node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return nil
		}
		node = node.Content[0]
	}
	for _, key := range path {
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				next = node.Content[i+1]
				break
			}
		}
		node = next
	}
	return node
}

// valueNode builds a YAML node for a supported Go value (bool, string, int,
// float64, []string).
func valueNode(v any) (*yaml.Node, error) {
	switch v.(type) {
	case bool, string, int, int64, float64, []string:
		var n yaml.Node
		data, err := yaml.Marshal(v)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, &n); err != nil {
			return nil, err
		}
		if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
			return n.Content[0], nil
		}
		return &n, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", v)
	}
}

// renderNode renders a value node to a compact human-readable string for diff
// display. A missing node renders as "(unset)".
func renderNode(n *yaml.Node) string {
	if n == nil {
		return "(unset)"
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value == "" {
			return `""`
		}
		return n.Value
	case yaml.SequenceNode:
		parts := make([]string, 0, len(n.Content))
		for _, c := range n.Content {
			parts = append(parts, c.Value)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case yaml.MappingNode:
		return "{…}"
	default:
		return ""
	}
}
