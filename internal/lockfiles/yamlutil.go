package lockfiles

import (
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxAliasHops bounds how many aliases are followed to reach a node: an alias
// can point at an alias.
const maxAliasHops = 16

// yamlResolve follows a document node to its content and an alias to its
// anchor.
func yamlResolve(n *yaml.Node) *yaml.Node {
	for hops := 0; n != nil && hops < maxAliasHops; hops++ {
		switch n.Kind {
		case yaml.DocumentNode:
			if len(n.Content) == 0 {
				return nil
			}
			n = n.Content[0]
		case yaml.AliasNode:
			n = n.Alias
		default:
			return n
		}
	}
	if n != nil && (n.Kind == yaml.AliasNode || n.Kind == yaml.DocumentNode) {
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

// yamlSequence returns n as a sequence, or nil.
func yamlSequence(n *yaml.Node) *yaml.Node {
	n = yamlResolve(n)
	if n == nil || n.Kind != yaml.SequenceNode {
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
		if k := yamlResolve(m.Content[i]); k != nil && k.Kind == yaml.ScalarNode && k.Value == key {
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
