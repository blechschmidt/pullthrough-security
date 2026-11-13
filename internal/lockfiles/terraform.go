package lockfiles

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// terraformLock reads the dependency lock file of Terraform and OpenTofu,
// .terraform.lock.hcl: a "provider" block per provider, named by its address
// ("registry.terraform.io/hashicorp/random"), with the selected version, the
// constraints it satisfies and its hashes:
//
//	zh:<hex>   the SHA-256 of a file of the provider release, as listed in its
//	           signed SHA256SUMS: one per platform's zip — and one of the
//	           release's manifest.json, which is no package (Digest.Of
//	           "terraform-zip")
//	h1:<b64>   Go's directory hash ("hash scheme 1") of one platform's
//	           unpacked package: SHA-256 over the sorted "<sha256>  <path>"
//	           lines of its files (Digest.Of "terraform-package")
//
// Terraform records which hashes it has seen, not which platform each is of.
// The lock file does not record modules: their pins are in the module blocks
// of the .tf files (terraformModules).
type terraformLock struct{}

func (terraformLock) Type() string            { return "terraform" }
func (terraformLock) Format() string          { return ".terraform.lock.hcl" }
func (terraformLock) Detect(path string) bool { return baseName(path) == ".terraform.lock.hcl" }

func (terraformLock) Parse(data []byte) (*Result, error) {
	body, err := parseHCL(data, "provider")
	if err != nil {
		return nil, err
	}
	res := &Result{}
	seen := map[string]bool{}
	for _, blk := range body.blocks {
		if blk.typ != "provider" {
			continue
		}
		if len(blk.labels) != 1 {
			res.warnf("line %d: a provider block without one address", blk.line)
			continue
		}
		addr := blk.labels[0]
		if seen[addr] {
			// Terraform refuses a lock file that locks a provider twice.
			return nil, fmt.Errorf("line %d: the provider %s is locked twice", blk.line, quoteName(addr))
		}
		seen[addr] = true
		host, name, ok := terraformProviderAddress(addr)
		if !ok {
			res.warnf("line %d: not a provider address", blk.line)
			continue
		}
		version := blk.body.attrs["version"]
		d := Dependency{Name: name, Line: blk.line, Registry: "https://" + host}
		if version != nil && version.isStr {
			d.Version = version.str
		}
		if !validVersion(d.Version) {
			res.warnf("line %d: %s: no version", blk.line, name)
			continue
		}
		if hashes := blk.body.attrs["hashes"]; hashes != nil && hashes.isList {
			for _, h := range hashes.list {
				if dg, ok := terraformHash(h); ok {
					d.Digests = append(d.Digests, dg)
				}
			}
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	if body.attrCount > 0 && body.blockCount == 0 {
		return nil, errNotFormat(".terraform.lock.hcl", "attributes and no provider blocks")
	}
	return res, nil
}

// terraformProviderAddress splits "<host>/<namespace>/<type>" (a bare
// "<namespace>/<type>" is on the default registry) into the host and
// "<namespace>/<type>", lower-cased as Terraform normalises them.
func terraformProviderAddress(addr string) (host, name string, ok bool) {
	parts := strings.Split(strings.ToLower(addr), "/")
	switch len(parts) {
	case 2:
		parts = append([]string{"registry.terraform.io"}, parts...)
	case 3:
	default:
		return "", "", false
	}
	for _, p := range parts {
		if !terraformNamePart(p) {
			return "", "", false
		}
	}
	return parts[0], parts[1] + "/" + parts[2], true
}

// terraformNamePart: the characters of a host, namespace, name or provider.
func terraformNamePart(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

// terraformHash reads "zh:<hex>" or "h1:<base64>".
func terraformHash(h string) (Digest, bool) {
	scheme, value, ok := strings.Cut(h, ":")
	if !ok {
		return Digest{}, false
	}
	switch scheme {
	case "zh":
		return hexDigest("sha256", value, "terraform-zip")
	case "h1":
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(raw) != 32 {
			return Digest{}, false
		}
		return Digest{Algorithm: "h1", Value: base64.StdEncoding.EncodeToString(raw), Of: "terraform-package"}, true
	}
	return Digest{}, false
}

// terraformModules reads the module blocks of a Terraform or OpenTofu
// configuration file (*.tf, *.tofu) — the module pins the lock file leaves
// out. A module from a registry is pinned by an exact "version"; a module
// from a Git repository by the commit its "?ref=" names (a tag or branch
// there pins nothing that cannot move). Terraform records no hash of a
// module, so a registry module is unverified. A file without module blocks
// yields nothing and is not reported.
type terraformModules struct{}

func (terraformModules) Type() string   { return "terraform" }
func (terraformModules) Format() string { return "*.tf modules" }
func (terraformModules) Detect(path string) bool {
	name := baseName(path)
	return len(name) > 3 && (strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tofu")) &&
		!(terraformOverrides{}).Detect(path)
}

// omitEmpty: most configuration files have no module block.
func (terraformModules) omitEmpty() bool { return true }

func (terraformModules) Parse(data []byte) (*Result, error) {
	blocks, err := terraformModuleBlocks(data)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	for i := range blocks {
		if d, ok := terraformModule(res, blocks[i].hclBlock); ok {
			blocks[i].dep = len(res.Dependencies)
			res.Dependencies = append(res.Dependencies, d)
		}
	}
	res.extra = blocks
	return res, nil
}

// tfModuleBlock is a module block as a file declares it, kept for the
// override files of the directory, with the dependency it yielded (-1 for
// none).
type tfModuleBlock struct {
	*hclBlock
	dep int
}

// terraformModuleBlocks reads the module blocks of a file, refusing a name
// declared twice, as Terraform refuses it.
func terraformModuleBlocks(data []byte) ([]tfModuleBlock, error) {
	body, err := parseHCL(data, "module")
	if err != nil {
		return nil, err
	}
	var out []tfModuleBlock
	seen := map[string]bool{}
	for _, blk := range body.blocks {
		if blk.typ != "module" || len(blk.labels) != 1 {
			continue
		}
		if seen[blk.labels[0]] {
			return nil, fmt.Errorf("line %d: the module %s is declared twice", blk.line, quoteName(blk.labels[0]))
		}
		seen[blk.labels[0]] = true
		out = append(out, tfModuleBlock{hclBlock: blk, dep: -1})
	}
	return out, nil
}

// terraformOverrides reads Terraform's override files — override.tf and
// *_override.tf (.tofu for OpenTofu) — whose module blocks replace the
// arguments of the module of the same name declared elsewhere in the
// directory: an override's version is the version Terraform installs. The
// files yield nothing of their own; Merge rewrites the dependencies of the
// modules they override, in the order Terraform applies them (by file name).
type terraformOverrides struct{}

func (terraformOverrides) Type() string   { return "terraform" }
func (terraformOverrides) Format() string { return "*.tf overrides" }
func (terraformOverrides) Detect(path string) bool {
	name := baseName(path)
	for _, ext := range []string{".tf", ".tofu"} {
		if stem, ok := strings.CutSuffix(name, ext); ok && (stem == "override" || strings.HasSuffix(stem, "_override")) {
			return true
		}
	}
	return false
}

// omitEmpty: an override file only changes what another file declares.
func (terraformOverrides) omitEmpty() bool { return true }

func (terraformOverrides) Parse(data []byte) (*Result, error) {
	blocks, err := terraformModuleBlocks(data)
	if err != nil {
		return nil, err
	}
	return &Result{extra: tfOverrideFile{blocks: blocks}}, nil
}

// tfOverrideFile is what an override file keeps for Merge.
type tfOverrideFile struct {
	blocks  []tfModuleBlock
	applied *bool
}

// Merge applies every override file of the directory to the module blocks
// of its other configuration files, once.
func (terraformOverrides) Merge(files []*File) {
	var overrides []*File
	for _, f := range files {
		if o, ok := f.extra.(tfOverrideFile); ok && f.Error == "" {
			if o.applied != nil {
				return // the directory's overrides are applied already
			}
			overrides = append(overrides, f)
		}
	}
	if len(overrides) == 0 {
		return
	}
	done := true
	for _, f := range overrides {
		o := f.extra.(tfOverrideFile)
		o.applied = &done
		f.extra = o
	}
	sort.Slice(overrides, func(i, j int) bool { return overrides[i].Path < overrides[j].Path })
	for _, of := range overrides {
		for _, ov := range of.extra.(tfOverrideFile).blocks {
			label := ov.labels[0]
			base, bi := findModuleBlock(files, label)
			if base == nil {
				of.addWarning(fmt.Sprintf("line %d: module %s overrides a module no other file of the directory declares", ov.line, quoteName(label)))
				continue
			}
			blocks := base.extra.([]tfModuleBlock)
			merged := &hclBlock{typ: "module", labels: blocks[bi].labels, line: blocks[bi].line, body: &hclBody{attrs: map[string]*hclAttr{}}}
			for k, v := range blocks[bi].body.attrs {
				merged.body.attrs[k] = v
			}
			for k, v := range ov.body.attrs {
				merged.body.attrs[k] = v // an override's argument replaces the original
			}
			tmp := &Result{}
			d, ok := terraformModule(tmp, merged)
			for _, w := range tmp.Warnings {
				base.addWarning(w)
			}
			base.addWarning(fmt.Sprintf("line %d: module %s is overridden in %s", blocks[bi].line, quoteName(label), baseName(of.Path)))
			switch {
			case ok && blocks[bi].dep >= 0:
				d.File, d.Type = base.Path, base.Type
				base.Dependencies[blocks[bi].dep] = d
			case ok:
				d.File, d.Type = base.Path, base.Type
				blocks[bi].dep = len(base.Dependencies)
				base.Dependencies = append(base.Dependencies, d)
			case blocks[bi].dep >= 0:
				// The override leaves nothing pinned: the original pin is gone.
				base.Dependencies = append(base.Dependencies[:blocks[bi].dep], base.Dependencies[blocks[bi].dep+1:]...)
				for i := range blocks {
					if blocks[i].dep > blocks[bi].dep {
						blocks[i].dep--
					}
				}
				blocks[bi].dep = -1
			}
			blocks[bi].hclBlock = merged
		}
	}
}

// findModuleBlock finds the configuration file of the directory that
// declares a module, and the block's index in it.
func findModuleBlock(files []*File, label string) (*File, int) {
	for _, f := range files {
		blocks, ok := f.extra.([]tfModuleBlock)
		if !ok || f.Error != "" {
			continue
		}
		for i, b := range blocks {
			if b.labels[0] == label {
				return f, i
			}
		}
	}
	return nil, -1
}

func terraformModule(res *Result, blk *hclBlock) (Dependency, bool) {
	label := quoteName(blk.labels[0])
	src := blk.body.attrs["source"]
	if src == nil || !src.isStr {
		res.warnf("line %d: module %s: its source is not a literal string", blk.line, label)
		return Dependency{}, false
	}
	source := strings.TrimSpace(src.str)
	ver := blk.body.attrs["version"]
	switch {
	case strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") || source == "." || source == "..":
		return Dependency{}, false // a module of this configuration
	case terraformRegistrySource(cutModuleSubdir(source)):
		// "ns/name/system//modules/x": a directory of the registry's module.
		host, name := terraformModuleAddress(cutModuleSubdir(source))
		if ver == nil || !ver.isStr {
			res.warnf("line %d: module %s: %s is not pinned to a version", blk.line, label, name)
			return Dependency{}, false
		}
		v, exact := terraformExactVersion(ver.str)
		if !exact {
			res.warnf("line %d: module %s: %s is constrained to a range, not pinned", blk.line, label, name)
			return Dependency{}, false
		}
		return Dependency{Name: name, Version: v, Registry: "https://" + host, Line: blk.line,
			UnverifiedReason: "Terraform records no hash of a module, only the version a module block pins"}, true
	}
	return terraformRemoteModule(res, blk, label, source)
}

// terraformRemoteModule reads a module from a repository or an archive URL
// (go-getter syntax: "git::https://…//subdir?ref=…", "github.com/o/r", …).
func terraformRemoteModule(res *Result, blk *hclBlock, label, source string) (Dependency, bool) {
	forced, rest, _ := strings.Cut(source, "::")
	if rest == "" {
		forced, rest = "", source
	}
	lower := strings.ToLower(rest)
	switch {
	case forced == "" && (strings.HasPrefix(lower, "github.com/") || strings.HasPrefix(lower, "bitbucket.org/")):
		forced, rest = "git", "https://"+rest
	case forced == "" && strings.HasPrefix(lower, "git@"):
		forced = "git"
	case forced == "" && isHTTPURL(rest):
		forced = "http"
	}
	// The query holds go-getter's parameters: ref, checksum, archive, depth.
	base, query, _ := strings.Cut(rest, "?")
	params, _ := url.ParseQuery(query)
	base = cutModuleSubdir(base)
	switch forced {
	case "git":
		d := Dependency{Name: blk.labels[0], Source: SourceGit, Registry: cleanGitRepoURL(base), Line: blk.line}
		ref := params.Get("ref")
		switch {
		case isCommitID(ref):
			d.Revision, d.Version = strings.ToLower(ref), strings.ToLower(ref)
		case ref != "":
			d.Version = ref // a tag or a branch: unverified
		default:
			res.warnf("line %d: module %s: a Git source without ?ref=, which follows the default branch", blk.line, label)
			return Dependency{}, false
		}
		if !validVersion(d.Version) || !validPackageName(d.Name) {
			res.warnf("line %d: module %s: not a usable reference", blk.line, label)
			return Dependency{}, false
		}
		return d, true
	case "http", "https":
		d := Dependency{Name: blk.labels[0], Source: SourceURL, URL: cleanURL(base), Line: blk.line}
		if c := params.Get("checksum"); c != "" {
			if dg, ok := prefixedDigest(c, ""); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		d.Version = fileNameOf(d.URL)
		if len(d.Digests) > 0 {
			d.Version = d.Digests[0].Algorithm + ":" + d.Digests[0].Value
		}
		if !validVersion(d.Version) || !validPackageName(d.Name) {
			res.warnf("line %d: module %s: not a usable archive URL", blk.line, label)
			return Dependency{}, false
		}
		return d, true
	}
	res.warnf("line %d: module %s: a source of a kind this parser does not read (%s)", blk.line, label, terraformSourceKind(forced, rest))
	return Dependency{}, false
}

// cutModuleSubdir drops the "//subdir" go-getter puts after a repository or
// archive to name a directory inside it.
func cutModuleSubdir(s string) string {
	start := 0
	if i := strings.Index(s, "://"); i >= 0 {
		start = i + 3
	}
	if j := strings.Index(s[start:], "//"); j >= 0 {
		return s[:start+j]
	}
	return s
}

// terraformSourceKind names a module source's kind for a warning without
// quoting it.
func terraformSourceKind(forced, rest string) string {
	if forced != "" {
		return forced
	}
	if i := strings.Index(rest, "://"); i > 0 && i < 16 {
		return rest[:i]
	}
	return "unrecognised"
}

// terraformRegistrySource reports whether a module source is a registry
// address: "<namespace>/<name>/<system>", optionally behind a host.
func terraformRegistrySource(s string) bool {
	if strings.Contains(s, "::") || strings.Contains(s, "://") || strings.ContainsAny(s, "?@ ") {
		return false
	}
	parts := strings.Split(s, "/")
	if len(parts) == 4 {
		if !strings.Contains(parts[0], ".") && !strings.Contains(parts[0], ":") || strings.EqualFold(parts[0], "github.com") || strings.EqualFold(parts[0], "bitbucket.org") {
			return false
		}
		parts = parts[1:]
	}
	if len(parts) != 3 || strings.ContainsAny(parts[0], ".:") {
		return false // "github.com/o/r" is a repository, not a namespace
	}
	for _, p := range parts {
		if !terraformNamePart(p) || strings.Contains(p, ":") {
			return false
		}
	}
	return true
}

// terraformModuleAddress splits a registry module source into its host and
// "<namespace>/<name>/<system>".
func terraformModuleAddress(s string) (host, name string) {
	parts := strings.Split(s, "/")
	host = "registry.terraform.io"
	if len(parts) == 4 {
		host, parts = strings.ToLower(parts[0]), parts[1:]
	}
	return host, strings.Join(parts, "/")
}

// terraformExactVersion returns the version a constraint pins exactly: "1.2.3"
// or "= 1.2.3". Any operator but "=", or more than one constraint, is a
// range.
func terraformExactVersion(c string) (string, bool) {
	c = strings.TrimSpace(c)
	if v, ok := strings.CutPrefix(c, "="); ok {
		c = strings.TrimSpace(v)
	}
	if c == "" || strings.ContainsAny(c, "<>=~!,* ") || c[0] < '0' || c[0] > '9' && c[0] != 'v' {
		return "", false
	}
	return strings.TrimPrefix(c, "v"), true
}
