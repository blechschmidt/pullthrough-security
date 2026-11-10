package mirror

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// PrewarmManifest is a declarative list of artifacts to pull into the cache
// before an instance is sealed. It is authored as YAML (or JSON, which is a
// subset) and consumed by a Warmer.
//
// Each entry names the upstream backend (by its configured route name, e.g.
// "npm", "pip", "dockerhub") and the request path under that backend — exactly
// the path a client would request through the proxy. Packages and images are
// separate sections purely for readability; they are warmed as one ordered work
// list (packages first, then images).
//
// Example:
//
//	packages:
//	  - upstream: npm
//	    path: /lodash/-/lodash-4.17.21.tgz
//	  - upstream: pip
//	    path: /packages/source/r/requests/requests-2.31.0.tar.gz
//	images:
//	  - upstream: dockerhub
//	    path: /v2/library/alpine/manifests/3.19
//	  - upstream: dockerhub
//	    path: /v2/library/alpine/blobs/sha256:abc...
type PrewarmManifest struct {
	Packages []PrewarmEntry `yaml:"packages" json:"packages"`
	Images   []PrewarmEntry `yaml:"images" json:"images"`
}

// PrewarmEntry is a single artifact to warm.
type PrewarmEntry struct {
	// Upstream is the configured backend route name (e.g. "npm", "dockerhub").
	Upstream string `yaml:"upstream" json:"upstream"`
	// Path is the request path under the backend, with a leading slash. It is the
	// same path a client would request through the proxy for this artifact.
	Path string `yaml:"path" json:"path"`
}

// Entries returns the packages followed by the images as a single ordered list,
// preserving authoring order so a warm run is deterministic.
func (m *PrewarmManifest) Entries() []PrewarmEntry {
	out := make([]PrewarmEntry, 0, len(m.Packages)+len(m.Images))
	out = append(out, m.Packages...)
	out = append(out, m.Images...)
	return out
}

// Validate checks that every entry is well-formed.
func (m *PrewarmManifest) Validate() error {
	entries := m.Entries()
	if len(entries) == 0 {
		return errors.New("mirror: prewarm manifest is empty")
	}
	for i, e := range entries {
		if strings.TrimSpace(e.Upstream) == "" {
			return fmt.Errorf("mirror: prewarm entry %d has empty upstream", i)
		}
		if strings.TrimSpace(e.Path) == "" {
			return fmt.Errorf("mirror: prewarm entry %d (%s) has empty path", i, e.Upstream)
		}
	}
	return nil
}

// ParsePrewarmManifest decodes a YAML/JSON prewarm manifest and validates it.
func ParsePrewarmManifest(r io.Reader) (*PrewarmManifest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("mirror: reading prewarm manifest: %w", err)
	}
	var m PrewarmManifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("mirror: parsing prewarm manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}
