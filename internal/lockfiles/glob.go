package lockfiles

import (
	"fmt"
	"path"
	"strings"
)

// glob is a compiled skip pattern.
type glob struct {
	// name is set for a pattern without "/": it matches a base name.
	name string
	// segs are the slash-separated segments of a path pattern; "**" matches
	// any number of segments.
	segs []string
}

// maxGlobs and maxGlobSegments bound the patterns a scan accepts.
const (
	maxGlobs        = 256
	maxGlobSegments = 64
)

// compileGlobs validates skip patterns.
func compileGlobs(patterns []string) ([]glob, error) {
	if len(patterns) > maxGlobs {
		return nil, fmt.Errorf("lockfiles: %d skip globs, at most %d", len(patterns), maxGlobs)
	}
	out := make([]glob, 0, len(patterns))
	for _, raw := range patterns {
		p := strings.Trim(strings.TrimSpace(raw), "/")
		if p == "" {
			return nil, fmt.Errorf("lockfiles: empty skip glob %q", raw)
		}
		if !strings.Contains(p, "/") {
			if p == "**" {
				out = append(out, glob{segs: []string{"**"}})
				continue
			}
			if _, err := path.Match(p, ""); err != nil {
				return nil, fmt.Errorf("lockfiles: skip glob %q: %w", raw, err)
			}
			out = append(out, glob{name: strings.ToLower(p)})
			continue
		}
		segs := strings.Split(p, "/")
		if len(segs) > maxGlobSegments {
			return nil, fmt.Errorf("lockfiles: skip glob %q has more than %d segments", raw, maxGlobSegments)
		}
		for _, s := range segs {
			if s == "" {
				return nil, fmt.Errorf("lockfiles: skip glob %q has an empty segment", raw)
			}
			if s == "**" {
				continue
			}
			if strings.Contains(s, "**") {
				return nil, fmt.Errorf("lockfiles: skip glob %q: \"**\" must be a whole segment", raw)
			}
			if _, err := path.Match(s, ""); err != nil {
				return nil, fmt.Errorf("lockfiles: skip glob %q: %w", raw, err)
			}
		}
		for i := range segs {
			segs[i] = strings.ToLower(segs[i])
		}
		out = append(out, glob{segs: segs})
	}
	return out, nil
}

// matchAny reports whether any glob matches the path p (whose last element is
// name). Matching ignores case: "Fixtures" and "Vendor" are skipped as
// "fixtures" and "vendor" are, as on the case-insensitive file systems many of
// these trees are checked out on.
func matchAny(globs []glob, p, name string) bool {
	p, name = strings.ToLower(p), strings.ToLower(name)
	var segs []string
	for _, g := range globs {
		if g.segs == nil {
			if ok, _ := path.Match(g.name, name); ok {
				return true
			}
			continue
		}
		if segs == nil {
			segs = strings.Split(p, "/")
		}
		if matchSegments(g.segs, segs) {
			return true
		}
	}
	return false
}

// matchSegments matches path segments against pattern segments, "**" matching
// zero or more segments. It runs in O(len(pat)·len(segs)) time: reach[j] says
// whether the pattern consumed so far can end just before segment j.
func matchSegments(pat, segs []string) bool {
	reach := make([]bool, len(segs)+1)
	reach[0] = true
	for _, ps := range pat {
		next := make([]bool, len(segs)+1)
		if ps == "**" {
			seen := false
			for j := 0; j <= len(segs); j++ {
				seen = seen || reach[j]
				next[j] = seen
			}
		} else {
			for j := 0; j < len(segs); j++ {
				if reach[j] {
					if ok, _ := path.Match(ps, segs[j]); ok {
						next[j+1] = true
					}
				}
			}
		}
		reach = next
	}
	return reach[len(segs)]
}
