package lockfiles

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// conanLock reads Conan's conan.lock in its two layouts:
//
//	Conan 2 ("version": "0.5")  "requires", "build_requires", "python_requires",
//	                            "config_requires": lists of references
//	                            "name/version[@user/channel]#rrev%timestamp"
//	Conan 1 ("version": "0.4")  "graph_lock": {"nodes": {id: {"ref", "package_id",
//	                            "prev", …}}}, node "0" the consumer itself
//
// A recipe revision (rrev) is, in Conan's default revision mode, the MD5 of
// the recipe's manifest — which lists the MD5 of every exported file — so it
// pins the recipe. Conan 2 locks no binary package: the package a client
// downloads is chosen by its package ID when it installs, and nothing here
// pins it, so a Conan 2 dependency is unverified. Conan 1 records the package
// revision (prev), the MD5 of the binary package's manifest, which pins it. A
// recipe revision in "scm" mode is a commit ID, not a digest.
type conanLock struct{}

func (conanLock) Type() string            { return "conan" }
func (conanLock) Format() string          { return "conan.lock" }
func (conanLock) Detect(path string) bool { return baseName(path) == "conan.lock" }

// conanLists are the reference lists of a Conan 2 lock file.
var conanLists = []string{"requires", "build_requires", "python_requires", "config_requires"}

func (conanLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	type ref struct {
		text string
		line int
		prev string
	}
	lists := map[string][]ref{}
	var nodes []ref
	sawContent := false
	err := doc.object(func(key string, _ int) error {
		switch key {
		case "version":
			v, err := jsonScalar(doc)
			res.FormatVersion = v
			return err
		case "graph_lock":
			sawContent = true
			nodes = nil
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			return doc.object(func(k string, _ int) error {
				if k != "nodes" || doc.peekKind() != '{' {
					return doc.skip()
				}
				byID := map[string]int{}
				return doc.object(func(id string, line int) error {
					f, err := doc.fields()
					if err != nil || f == nil {
						return err
					}
					r := ref{text: f.str("ref"), line: line, prev: f.str("prev")}
					if i, dup := byID[id]; dup {
						nodes[i] = r // a repeated node keeps its last value
						return nil
					}
					byID[id] = len(nodes)
					nodes = append(nodes, r)
					return nil
				})
			})
		}
		for _, l := range conanLists {
			if key == l {
				sawContent = true
				if doc.peekKind() != '[' {
					return doc.skip()
				}
				var refs []ref
				err := doc.array(func(_, line int) error {
					s, err := doc.stringValue()
					if err == nil && s != "" {
						refs = append(refs, ref{text: s, line: line})
					}
					return err
				})
				lists[key] = refs
				return err
			}
		}
		return doc.skip()
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	if !sawContent && res.FormatVersion == "" {
		return nil, errNotFormat("conan.lock", "no version and no requirements")
	}
	// Conan 2 reads the reference lists of a version 0.5 file, Conan 1 the
	// graph of an older one; neither reads the other's section, which is
	// refused rather than read.
	conan2 := res.FormatVersion == "0.5"
	switch {
	case conan2 && nodes != nil:
		return nil, errors.New("conan.lock version 0.5 with a Conan 1 graph_lock")
	case !conan2 && len(lists) > 0:
		return nil, fmt.Errorf("conan.lock version %s with Conan 2 reference lists", quoteName(res.FormatVersion))
	case !conan2 && !strings.HasPrefix(res.FormatVersion, "0."):
		return nil, fmt.Errorf("conan.lock version %s, which Conan does not read", quoteName(res.FormatVersion))
	}
	add := func(r ref) {
		if r.text == "" {
			return // the consumer node of a Conan 1 lock file
		}
		d, ok := conanDependency(r.text, r.line)
		if !ok {
			res.warnf("line %d: not a Conan reference", r.line)
			return
		}
		if dg, ok := hexDigest("md5", r.prev, "conan-package"); ok {
			d.Digests = append(d.Digests, dg)
		}
		res.add(d)
	}
	for _, l := range conanLists {
		for _, r := range lists[l] {
			add(r)
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].line < nodes[j].line })
	for _, r := range nodes {
		add(r)
	}
	return res, nil
}

// conanDependency reads "name/version[@user[/channel]][#rrev[%timestamp]]".
func conanDependency(ref string, line int) (Dependency, bool) {
	base, rrev, _ := strings.Cut(ref, "#")
	rrev, ts, _ := strings.Cut(rrev, "%")
	if ts != "" {
		if _, err := strconv.ParseFloat(ts, 64); err != nil {
			return Dependency{}, false
		}
	}
	nameVersion, userChannel, hasUser := strings.Cut(base, "@")
	name, version, ok := strings.Cut(nameVersion, "/")
	if !ok || !validConanPart(name) || !validConanPart(version) {
		return Dependency{}, false
	}
	d := Dependency{Name: name, Version: version, Line: line}
	if hasUser && userChannel != "" && userChannel != "_/_" {
		user, channel, _ := strings.Cut(userChannel, "/")
		if !validConanPart(user) || channel != "" && !validConanPart(channel) {
			return Dependency{}, false
		}
		d.ID = base
	}
	if dg, ok := hexDigest("md5", rrev, "conan-recipe"); ok {
		d.Digests = append(d.Digests, dg)
	}
	return d, true
}

// validConanPart: the characters of a Conan name, exact version, user or
// channel (a version range has others, and is no pin).
func validConanPart(s string) bool {
	if s == "" || len(s) > 101 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '+' || c == '.') {
			return false
		}
	}
	return true
}
