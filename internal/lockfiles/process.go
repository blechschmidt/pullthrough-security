package lockfiles

import (
	"fmt"
	"sort"
	"strings"
)

// File is the outcome for one lock file.
type File struct {
	// Path is the file's path in the repository (slash-separated).
	Path string `json:"path"`
	// Type is the upstream type of the format; Format names the format and
	// FormatVersion the version the file declares.
	Type          string `json:"type"`
	Format        string `json:"format"`
	FormatVersion string `json:"formatVersion,omitempty"`
	// Dependencies are the exact dependencies the file pins, in file order.
	Dependencies []Dependency `json:"dependencies"`
	// Warnings describe entries that did not become dependencies.
	Warnings []string `json:"warnings,omitempty"`
	// Error is why the file could not be read, when it could not.
	Error string `json:"error,omitempty"`

	parser Parser
}

// ParseFile parses one file with the parser that detects it, and finishes the
// result the way Scan does: dependencies attributed to the file, URLs mapped
// through proxy (which may be nil) and stripped of credentials and link
// tokens, duplicates merged. It returns nil when no parser detects path.
func ParseFile(reg *Registry, proxy *Proxy, path string, data []byte) *File {
	if reg == nil {
		reg = DefaultRegistry()
	}
	p := reg.Detect(path)
	if p == nil {
		return nil
	}
	f := parseOne(p, path, data)
	finish([]*File{f}, proxy)
	return f
}

// parseOne runs a parser over one file. A parser that panics fails the file,
// not the scan: parsers are fuzzed, but the walk must survive the input nobody
// thought of.
func parseOne(p Parser, filePath string, data []byte) (f *File) {
	f = &File{Path: filePath, Type: p.Type(), Format: p.Format(), parser: p}
	defer func() {
		if r := recover(); r != nil {
			f.Dependencies = nil
			f.Error = fmt.Sprintf("the %s parser failed on this file", p.Format())
		}
	}()
	res, err := p.Parse(data)
	if err != nil {
		f.Error = err.Error()
		return f
	}
	if res == nil {
		return f
	}
	f.FormatVersion = res.FormatVersion
	f.Warnings = res.Warnings
	f.Dependencies = res.Dependencies
	for i := range f.Dependencies {
		d := &f.Dependencies[i]
		d.File = filePath
		if d.Type == "" {
			d.Type = p.Type()
		}
	}
	return f
}

// finish completes parsed files: siblings merged (go.mod and go.sum), URLs
// mapped and redacted, duplicates collapsed, text redacted.
func finish(files []*File, proxy *Proxy) {
	byDir := map[string][]*File{}
	var dirs []string
	for _, f := range files {
		d := dirName(f.Path)
		if _, ok := byDir[d]; !ok {
			dirs = append(dirs, d)
		}
		byDir[d] = append(byDir[d], f)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		group := byDir[d]
		for _, f := range group {
			if m, ok := f.parser.(Merger); ok && f.Error == "" {
				m.Merge(group)
			}
		}
	}

	prefix := proxy.linkPrefix()
	for _, f := range files {
		for i := range f.Dependencies {
			if w := proxy.finishDependency(&f.Dependencies[i]); w != "" {
				f.Warnings = append(f.Warnings, w)
			}
		}
		f.Dependencies = dedupe(f.Dependencies)
		for i, w := range f.Warnings {
			f.Warnings[i] = redactText(w, prefix)
		}
		f.Error = redactText(f.Error, prefix)
		f.FormatVersion = redactText(f.FormatVersion, prefix)
		if f.Dependencies == nil {
			f.Dependencies = []Dependency{}
		}
	}
}

// dedupe collapses repeated dependencies onto their first entry, merging the
// digests, and orders the rest by line.
func dedupe(deps []Dependency) []Dependency {
	if len(deps) == 0 {
		return deps
	}
	index := map[string]int{}
	out := deps[:0:0]
	for _, d := range deps {
		k := d.Key()
		if i, ok := index[k]; ok {
			out[i].Digests = mergeDigests(out[i].Digests, d.Digests)
			if d.Line > 0 && (out[i].Line == 0 || d.Line < out[i].Line) {
				out[i].Line = d.Line
			}
			out[i].Dev = out[i].Dev && d.Dev
			if out[i].URL == "" {
				out[i].URL = d.URL
			}
			continue
		}
		index[k] = len(out)
		d.Digests = mergeDigests(nil, d.Digests)
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// mergeDigests appends the digests of b not already in a (or earlier in b),
// in linear time: one requirement can carry thousands of hashes.
func mergeDigests(a, b []Digest) []Digest {
	if len(b) == 0 {
		return a
	}
	seen := make(map[Digest]bool, len(a)+len(b))
	for _, d := range a {
		seen[d] = true
	}
	for _, d := range b {
		if d.Algorithm == "" || d.Value == "" || seen[d] {
			continue
		}
		seen[d] = true
		a = append(a, d)
	}
	return a
}

// finishDependency maps a dependency's URLs back from the proxy and strips
// their credentials. It returns a warning when the lock file names a proxy
// upstream of another type.
func (p *Proxy) finishDependency(d *Dependency) string {
	prefix := p.linkPrefix()
	if d.Type == "docker" {
		p.finishImage(d)
		return ""
	}
	var upstreams []mapped
	if d.Registry != "" {
		if m, ok := p.mapURL(d.Registry); ok {
			d.Registry = m.url
			if m.upstream != "" {
				upstreams = append(upstreams, m)
				if m.upstreamURL != "" {
					d.Registry = m.upstreamURL
				}
			}
		} else {
			d.Registry = redactText(sanitizeURL(d.Registry), prefix)
		}
	}
	if d.URL != "" {
		if m, ok := p.mapURL(d.URL); ok {
			d.URL = m.url
			if m.upstream != "" {
				upstreams = append(upstreams, m)
				if d.Registry == "" {
					d.Registry = m.upstreamURL
				}
			}
		} else {
			d.URL = redactText(sanitizeURL(d.URL), prefix)
		}
	}
	d.Name = redactText(d.Name, prefix)
	d.Version = redactText(d.Version, prefix)
	d.Revision = redactText(d.Revision, prefix)
	for i := range d.Digests {
		// A file name taken from a URL can be the URL's last segment.
		d.Digests[i].Of = redactText(d.Digests[i].Of, prefix)
	}
	if len(upstreams) == 0 {
		return ""
	}
	m := upstreams[0]
	d.Upstream = m.upstream
	if d.Registry == "" {
		d.Registry = m.mount
	}
	if m.upstreamType != "" && m.upstreamType != CanonicalType(d.Type) {
		return fmt.Sprintf("%s %s: the lock file resolves it through proxy upstream %q, which is a %s upstream",
			d.Name, d.Version, m.upstream, m.upstreamType)
	}
	return ""
}

// cleanURL strips what a parser must not pass on from a URL it read: the
// userinfo, the query, the fragment, and every path segment spelled like a
// personal link token (cut down to the bare prefix, which keeps the shape the
// proxy mapping recognises and nothing of the secret).
func cleanURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	raw = stripUserinfo(raw)
	return tokenRun.ReplaceAllString(raw, linkTokenPrefix)
}
