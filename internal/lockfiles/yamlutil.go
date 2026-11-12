package lockfiles

import (
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAML is read into yaml.v3's node tree, which does not expand aliases. The
// helpers below do not follow them either: no tool writes an alias into a
// lock file, and following one lets a small document stand for a huge one —
// a hundred thousand entries that all alias one mapping of a hundred thousand
// keys is a quadratic amount of work from a few megabytes. Compose files do
// use anchors and merge keys; composeResolver follows them under a budget.

// yamlResolve follows a document node to its content. An alias resolves to
// nothing.
func yamlResolve(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		n = n.Content[0]
	}
	if n == nil || n.Kind == yaml.AliasNode {
		return nil
	}
	return n
}

// yamlMapping returns n as a mapping, or nil.
func yamlMapping(n *yaml.Node) *yaml.Node {
	n = yamlResolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

// yamlGet returns the value of key in mapping m, or nil.
func yamlGet(m *yaml.Node, key string) *yaml.Node {
	m = yamlMapping(m)
	if m == nil {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; k.Kind == yaml.ScalarNode && k.Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// yamlScalar returns n's value when it is a scalar, else "".
func yamlScalar(n *yaml.Node) string {
	n = yamlResolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// yamlError describes a YAML syntax error by its first line.
func yamlError(err error) error {
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return errors.New(msg)
}

// Bounds of composeResolver.
const (
	// maxAliasHops bounds a chain of aliases.
	maxAliasHops = 16
	// maxMergeDepth bounds how deeply "<<" merge keys are followed.
	maxMergeDepth = 8
	// composeBudget is how many mapping entries one Compose document may make
	// the resolver look at, aliases and merges included.
	composeBudget = 1_000_000
)

var errComposeBudget = errors.New("compose file: too much aliasing to resolve")

// composeResolver reads a Compose document, following aliases and merge keys,
// with every mapping entry it looks at counted against a budget.
type composeResolver struct {
	budget int
}

func newComposeResolver() *composeResolver { return &composeResolver{budget: composeBudget} }

// resolve follows aliases (a bounded chain) to a node.
func (c *composeResolver) resolve(n *yaml.Node) *yaml.Node {
	for hops := 0; n != nil && n.Kind == yaml.AliasNode; hops++ {
		if hops >= maxAliasHops {
			return nil
		}
		n = n.Alias
	}
	return yamlResolve(n)
}

// mapping returns n, after aliases, as a mapping.
func (c *composeResolver) mapping(n *yaml.Node) *yaml.Node {
	n = c.resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

// get looks key up in mapping m and, failing that, in the mappings merged
// into it with "<<" — each mapping once.
func (c *composeResolver) get(m *yaml.Node, key string) (*yaml.Node, error) {
	return c.getMerged(c.mapping(m), key, 0, map[*yaml.Node]bool{})
}

func (c *composeResolver) getMerged(m *yaml.Node, key string, depth int, seen map[*yaml.Node]bool) (*yaml.Node, error) {
	if m == nil || seen[m] || depth > maxMergeDepth {
		return nil, nil
	}
	seen[m] = true
	c.budget -= len(m.Content)/2 + 1
	if c.budget < 0 {
		return nil, errComposeBudget
	}
	var merge *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := c.resolve(m.Content[i])
		if k == nil || k.Kind != yaml.ScalarNode {
			continue
		}
		switch k.Value {
		case key:
			return m.Content[i+1], nil
		case "<<":
			merge = c.resolve(m.Content[i+1])
		}
	}
	if merge == nil {
		return nil, nil
	}
	sources := []*yaml.Node{merge}
	if merge.Kind == yaml.SequenceNode {
		sources = merge.Content
	}
	for _, src := range sources {
		v, err := c.getMerged(c.mapping(src), key, depth+1, seen)
		if err != nil || v != nil {
			return v, err
		}
	}
	return nil, nil
}
