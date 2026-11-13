package lockfiles

import (
	"encoding/hex"
	"strings"
)

// flakeLock reads a Nix flake's flake.lock: a graph of nodes — "root" the
// flake itself — each input "locked" to an exact source:
//
//	github, gitlab, sourcehut   owner, repo, rev (a commit), host
//	git, hg                     url, rev
//	tarball, file               url
//	path                        a directory on the local file system
//
// and every locked source with its "narHash": the SHA-256 of the NAR
// serialisation of the source tree, which Nix checks after fetching it
// (Digest.Of "nar"). An input is a source repository or archive, not a store
// path of the binary cache: the dependency is what is fetched to evaluate the
// flake. A repository input is a Git dependency named by its flake reference
// ("github:NixOS/nixpkgs"), its version the commit; an archive input is named
// by its URL and versioned by its NAR hash.
type flakeLock struct{}

func (flakeLock) Type() string            { return "nix" }
func (flakeLock) Format() string          { return "flake.lock" }
func (flakeLock) Detect(path string) bool { return baseName(path) == "flake.lock" }

// flakeForges are the default hosts of the forge input types.
var flakeForges = map[string]string{"github": "github.com", "gitlab": "gitlab.com", "sourcehut": "git.sr.ht"}

func (flakeLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	type node struct {
		key    string
		locked jsonFields
		line   int
	}
	var nodes []node
	rootName := "root"
	sawNodes := false
	err := doc.object(func(key string, _ int) error {
		switch key {
		case "version":
			v, err := jsonScalar(doc)
			res.FormatVersion = v
			return err
		case "root":
			s, err := doc.stringValue()
			if s != "" {
				rootName = s
			}
			return err
		case "nodes":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			sawNodes = true
			nodes = nil
			byKey := map[string]int{}
			return doc.object(func(k string, line int) error {
				f, err := doc.fields()
				if err != nil || f == nil {
					return err
				}
				n := node{key: k, locked: f.obj("locked"), line: line}
				if i, dup := byKey[k]; dup {
					nodes[i] = n // a repeated node keeps its last value
					return nil
				}
				byKey[k] = len(nodes)
				nodes = append(nodes, n)
				return nil
			})
		}
		return doc.skip()
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	if !sawNodes {
		return nil, errNotFormat("flake.lock", "no nodes")
	}
	for _, n := range nodes {
		if n.key == rootName || n.locked == nil {
			continue
		}
		if d, ok := flakeDependency(res, n.key, n.locked, n.line); ok {
			res.add(d)
		}
	}
	return res, nil
}

func flakeDependency(res *Result, key string, l jsonFields, line int) (Dependency, bool) {
	typ := l.str("type")
	nar, hasNar := narDigest(l.str("narHash"))
	d := Dependency{Line: line}
	if hasNar {
		d.Digests = []Digest{nar}
	}
	rev := strings.ToLower(l.str("rev"))
	switch {
	case flakeForges[typ] != "":
		owner, repo := l.str("owner"), l.str("repo")
		if !flakePart(owner) || !flakePart(repo) {
			res.warnf("input %s: a %s input without a usable owner or repository", quoteName(key), typ)
			return Dependency{}, false
		}
		host := flakeForges[typ]
		if h := l.str("host"); h != "" {
			if !flakePart(h) {
				res.warnf("input %s: a host that is not a host name", quoteName(key))
				return Dependency{}, false
			}
			host = strings.ToLower(h)
		}
		d.Name = typ + ":" + owner + "/" + repo
		d.Source, d.Registry = SourceGit, "https://"+host+"/"+owner+"/"+repo
	case typ == "git" || typ == "hg":
		u := l.str("url")
		if !isHTTPURL(u) && !strings.HasPrefix(strings.ToLower(u), "ssh://") && !strings.HasPrefix(strings.ToLower(u), "git://") {
			res.warnf("input %s: a %s repository that is not fetched over the network", quoteName(key), typ)
			return Dependency{}, false
		}
		d.Source, d.Registry = SourceGit, cleanGitRepoURL(u)
		d.Name = typ + "+" + d.Registry
		if typ == "hg" {
			res.warnf("input %s: a Mercurial repository", quoteName(key))
		}
	case typ == "tarball" || typ == "file":
		u := l.str("url")
		if !isHTTPURL(u) {
			res.warnf("input %s: a %s input that is not fetched over HTTP", quoteName(key), typ)
			return Dependency{}, false
		}
		d.Source, d.URL = SourceURL, cleanURL(u)
		d.Name = d.URL
		if hasNar {
			d.Version = "sha256:" + nar.Value
		} else {
			d.Version = fileNameOf(d.URL) // nothing pins it: unverified
		}
	case typ == "path":
		res.warnf("input %s: a local path, not fetched", quoteName(key))
		return Dependency{}, false
	default:
		res.warnf("input %s: a locked input of type %q, which this parser does not read", quoteName(key), typ)
		return Dependency{}, false
	}
	if d.Source == SourceGit {
		switch {
		case isCommitID(rev):
			d.Revision, d.Version = rev, rev
		case hasNar:
			// No commit, but Nix checks the fetched tree against the NAR hash.
			d.Version = "sha256:" + nar.Value
		default:
			res.warnf("input %s: locked without a commit or a NAR hash", quoteName(key))
			return Dependency{}, false
		}
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("input %s: no usable name or version", quoteName(key))
		return Dependency{}, false
	}
	return d, true
}

// flakePart reports whether s can be an owner, repository or host name in a
// flake reference.
func flakePart(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._-~:", c) >= 0) {
			return false
		}
	}
	return true
}

// narDigest reads a NAR hash: SRI ("sha256-<base64>"), or the older
// "sha256:<nix base-32>" / "sha256:<hex>".
func narDigest(s string) (Digest, bool) {
	if v, ok := strings.CutPrefix(s, "sha256-"); ok {
		return base64Digest("sha256", v, "nar")
	}
	if v, ok := strings.CutPrefix(s, "sha256:"); ok {
		if dg, ok := hexDigest("sha256", v, "nar"); ok {
			return dg, true
		}
		if raw, ok := nixBase32Decode(v, 32); ok {
			return Digest{Algorithm: "sha256", Value: hex.EncodeToString(raw), Of: "nar"}, true
		}
	}
	return Digest{}, false
}

// nixBase32Alphabet is Nix's base-32 digit set (libutil/hash.cc): no "e",
// "o", "u" or "t", digits read least-significant first.
const nixBase32Alphabet = "0123456789abcdfghijklmnpqrsvwxyz"

// nixBase32Decode decodes Nix's base-32 text of a size-byte hash, refusing a
// character outside the alphabet or padding bits that are not zero.
func nixBase32Decode(s string, size int) ([]byte, bool) {
	if len(s) != (size*8-1)/5+1 {
		return nil, false
	}
	out := make([]byte, size)
	for n := 0; n < len(s); n++ {
		digit := strings.IndexByte(nixBase32Alphabet, s[len(s)-1-n])
		if digit < 0 {
			return nil, false
		}
		b := n * 5
		i, bit := b/8, b%8
		out[i] |= byte(digit << bit)
		carry := byte(digit >> (8 - bit))
		if i+1 < size {
			out[i+1] |= carry
		} else if carry != 0 {
			return nil, false
		}
	}
	return out, true
}
