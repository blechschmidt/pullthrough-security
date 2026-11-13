package lockfiles

import (
	"errors"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// condaLock reads conda-lock's unified lock file, conda-lock.yml: every
// package of every platform, with the manager that installs it ("conda", or
// "pip" for the PyPI packages of an environment), its download URL and its
// hashes — the MD5 and SHA-256 of the package file for conda, the SHA-256 of
// the wheel or sdist for pip. The same package version is a separate file
// per platform; it is one dependency, with each file's hashes (Digest.Of is
// "<subdir>/<file name>" for conda, the file name for pip). A package of the
// "dev" category, or an optional one, is development-only.
type condaLock struct{}

func (condaLock) Type() string   { return "conda" }
func (condaLock) Format() string { return "conda-lock.yml" }
func (condaLock) Detect(path string) bool {
	name := baseName(path)
	return name == "conda-lock.yml" || name == "conda-lock.yaml" ||
		strings.HasSuffix(name, ".conda-lock.yml") || strings.HasSuffix(name, ".conda-lock.yaml")
}

func (condaLock) Parse(data []byte) (*Result, error) {
	m, err := readYAMLLock(data, "conda-lock.yml")
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errNotFormat("conda-lock.yml", "empty")
	}
	res := &Result{FormatVersion: yamlScalar(yamlGet(m, "version"))}
	packages := yamlGet(m, "package")
	if res.FormatVersion == "" && packages == nil {
		return nil, errNotFormat("conda-lock.yml", "no version and no packages")
	}
	for _, p := range yamlSeq(packages) {
		if d, ok := condaLockDependency(res, p); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
	}
	return res, nil
}

func condaLockDependency(res *Result, p *yaml.Node) (Dependency, bool) {
	name, version := yamlScalar(yamlGet(p, "name")), yamlScalar(yamlGet(p, "version"))
	manager, rawURL := yamlScalar(yamlGet(p, "manager")), yamlScalar(yamlGet(p, "url"))
	line := p.Line
	category := yamlScalar(yamlGet(p, "category"))
	d := Dependency{Name: name, Version: version, Line: line,
		Dev: category == "dev" || yamlScalar(yamlGet(p, "optional")) == "true"}
	hash := yamlGet(p, "hash")
	switch manager {
	case "conda", "":
		if !isHTTPURL(rawURL) {
			res.warnf("line %d: %s: a package without an HTTP URL", line, name)
			return Dependency{}, false
		}
		channel, file, ok := condaChannelFile(rawURL)
		if !ok {
			res.warnf("line %d: %s: a URL that names no package file", line, name)
			return Dependency{}, false
		}
		d.Registry, d.URL = channel, cleanURL(rawURL)
		// conda-lock installs the file at the URL: the name and version are
		// the file's, whatever the entry says.
		if fn, fv, _, ok := condaFileParts(fileNameOf(file)); ok {
			if fn != name || fv != version {
				res.warnf("line %d: the entry says %s %s, its URL is the file of %s %s, which is what is installed", line, quoteName(name), quoteName(version), quoteName(fn), quoteName(fv))
			}
			d.Name, d.Version = fn, fv
		}
		for _, alg := range []string{"sha256", "md5"} {
			if dg, ok := hexDigest(alg, yamlScalar(yamlGet(hash, alg)), file); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
	case "pip":
		d.Type, d.Name = "pip", pyNormalize(name)
		switch {
		case strings.HasPrefix(rawURL, "git+"):
			// "git+https://host/repo.git@<commit>": the commit pins it (conda-lock
			// writes the commit into hash.sha256 as well, where it is no hash).
			base, rev := rawURL, ""
			if i := strings.LastIndexByte(rawURL, '@'); i > strings.LastIndexByte(rawURL, '/') {
				base, rev = rawURL[:i], rawURL[i+1:]
			}
			d.Source, d.Registry = SourceGit, cleanGitRepoURL(base)
			if isCommitID(rev) {
				d.Revision = strings.ToLower(rev)
			}
			if !validPackageName(d.Name) || !validVersion(d.Version) {
				res.warnf("line %d: a package without a usable name or version", line)
				return Dependency{}, false
			}
			return d, true
		case isHTTPURL(rawURL):
			d.URL = cleanURL(rawURL)
			// pip installs the file at the URL: a wheel's or sdist's name and
			// version are the file's.
			if fn, fv, ok := pyDistNameVersion(fileNameOf(d.URL)); ok {
				if fn != d.Name || fv != d.Version {
					res.warnf("line %d: the entry says %s %s, its URL is the file of %s %s, which is what is installed", line, quoteName(d.Name), quoteName(d.Version), quoteName(fn), quoteName(fv))
				}
				d.Name, d.Version = fn, fv
			}
		case rawURL != "":
			res.warnf("line %d: %s: a pip package from a location that is not an HTTP URL", line, name)
			return Dependency{}, false
		}
		of := fileNameOf(cleanURL(rawURL))
		if dg, ok := hexDigest("sha256", yamlScalar(yamlGet(hash, "sha256")), of); ok {
			d.Digests = append(d.Digests, dg)
		}
	default:
		res.warnf("line %d: %s: installed by %q, which this parser does not read", line, name, manager)
		return Dependency{}, false
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: a package without a usable name or version", line)
		return Dependency{}, false
	}
	return d, true
}

// pyDistNameVersion reads the normalised project name and the version from
// a wheel's or an sdist's file name ("six-1.16.0-py2.py3-none-any.whl",
// "pkg-1.0.tar.gz").
func pyDistNameVersion(file string) (name, version string, ok bool) {
	var base string
	switch {
	case strings.HasSuffix(file, ".whl"):
		parts := strings.Split(strings.TrimSuffix(file, ".whl"), "-")
		if len(parts) < 5 {
			return "", "", false
		}
		name, version = parts[0], parts[1]
	case strings.HasSuffix(file, ".tar.gz"), strings.HasSuffix(file, ".zip"):
		base = strings.TrimSuffix(strings.TrimSuffix(file, ".tar.gz"), ".zip")
		i := strings.LastIndexByte(base, '-')
		if i <= 0 {
			return "", "", false
		}
		name, version = base[:i], base[i+1:]
	default:
		return "", "", false
	}
	if name == "" || version == "" {
		return "", "", false
	}
	return pyNormalize(name), version, true
}

// condaChannelFile splits a package URL into the channel URL and
// "<subdir>/<file name>": ".../conda-forge/linux-64/zlib-1.3.1-h_2.conda" →
// ".../conda-forge", "linux-64/zlib-1.3.1-h_2.conda".
func condaChannelFile(raw string) (channel, file string, ok bool) {
	clean := cleanURL(raw)
	i := strings.LastIndexByte(clean, '/')
	if i <= 0 {
		return "", "", false
	}
	j := strings.LastIndexByte(clean[:i], '/')
	if j <= 0 || !condaPackageFile(clean[i+1:]) {
		return "", "", false
	}
	return clean[:j], clean[j+1:], true
}

// condaPackageFile reports whether name is a conda package file name.
func condaPackageFile(name string) bool {
	_, _, _, ok := condaFileParts(name)
	return ok
}

// condaFileParts splits "<name>-<version>-<build>.conda" (or .tar.bz2);
// neither the version nor the build contains a hyphen.
func condaFileParts(file string) (name, version, build string, ok bool) {
	base, cut := strings.CutSuffix(file, ".conda")
	if !cut {
		if base, cut = strings.CutSuffix(file, ".tar.bz2"); !cut {
			return "", "", "", false
		}
	}
	j := strings.LastIndexByte(base, '-')
	if j <= 0 {
		return "", "", "", false
	}
	i := strings.LastIndexByte(base[:j], '-')
	if i <= 0 {
		return "", "", "", false
	}
	name, version, build = base[:i], base[i+1:j], base[j+1:]
	if name == "" || version == "" || build == "" {
		return "", "", "", false
	}
	return name, version, build, true
}

// condaExplicit reads an explicit spec file — what `conda list --explicit`
// and conda-lock's "explicit" kind write: comments, an "@EXPLICIT" line, then
// one package URL per line, its MD5 or SHA-256 as the fragment ("--md5",
// "--sha256"; conda writes either as bare hex). Every line is a package file
// of one platform; the name, version and build come from the file name.
// conda-lock adds the environment's PyPI packages as "# pip <name> @ <url>"
// comments, which `conda-lock install` installs: they are read too.
type condaExplicit struct{}

func (condaExplicit) Type() string   { return "conda" }
func (condaExplicit) Format() string { return "@EXPLICIT spec" }

// Detect accepts the names conda-lock writes (conda-<platform>.lock, and
// "*.conda.lock" as its documentation suggests) and spec-file.txt, conda's
// documented example.
func (condaExplicit) Detect(path string) bool {
	name := baseName(path)
	return strings.HasPrefix(name, "conda-") && strings.HasSuffix(name, ".lock") && len(name) > len("conda-.lock") ||
		strings.HasSuffix(name, ".conda.lock") || name == "spec-file.txt"
}

func (condaExplicit) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("explicit spec file is not valid UTF-8")
	}
	res := &Result{}
	explicit := false
	// conda reads the file in Python's text mode, whose universal newlines
	// end a line at a lone carriage return too.
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	for it := newLineIter(text); ; {
		raw, lineNo, more := it.next()
		if !more {
			break
		}
		line := strings.TrimSpace(raw)
		switch {
		case explicit && strings.HasPrefix(line, "# pip "):
			// conda-lock lists an environment's PyPI packages as comments that
			// `conda-lock install` installs: "# pip <name> @ <url>".
			name, loc, ok := strings.Cut(strings.TrimPrefix(line, "# pip "), " @ ")
			if !ok || !pyNameRE.MatchString(strings.TrimSpace(name)) {
				res.warnf("line %d: a pip line this parser does not understand", lineNo)
				continue
			}
			if d, ok := reqDirect(res, pyNormalize(strings.TrimSpace(name)), strings.TrimSpace(loc), nil, lineNo); ok {
				d.Type = "pip"
				res.Dependencies = append(res.Dependencies, d)
			}
			continue
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case line == "@EXPLICIT":
			explicit = true
			continue
		case !explicit:
			return nil, errNotFormat("explicit spec file", "a line before @EXPLICIT")
		}
		if d, ok := condaExplicitLine(res, line, lineNo); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
	}
	if !explicit {
		return nil, errNotFormat("explicit spec file", "no @EXPLICIT line")
	}
	return res, nil
}

func condaExplicitLine(res *Result, line string, lineNo int) (Dependency, bool) {
	loc, frag, _ := strings.Cut(line, "#")
	if !isHTTPURL(loc) {
		res.warnf("line %d: not a package URL", lineNo)
		return Dependency{}, false
	}
	channel, file, ok := condaChannelFile(loc)
	if !ok {
		res.warnf("line %d: a URL that names no package file", lineNo)
		return Dependency{}, false
	}
	name, version, _, _ := condaFileParts(fileNameOf(file))
	d := Dependency{Name: name, Version: version, Registry: channel, URL: cleanURL(loc), Line: lineNo}
	frag = strings.TrimSpace(frag)
	if dg, ok := prefixedDigest(frag, file); ok {
		d.Digests = append(d.Digests, dg)
	} else if dg, ok := hexDigest("md5", frag, file); ok {
		d.Digests = append(d.Digests, dg)
	} else if dg, ok := hexDigest("sha256", frag, file); ok {
		d.Digests = append(d.Digests, dg)
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: a package file without a usable name or version", lineNo)
		return Dependency{}, false
	}
	return d, true
}

// pixiLock reads pixi's pixi.lock: per environment and platform the
// packages installed, and under "packages" one record per package file —
// "conda: <url>" with the file's SHA-256 and MD5, or "pypi: <url>" with the
// name, version and (for a wheel or sdist) SHA-256. Versions 6 and 7 name a
// conda package only by its URL, so its name, version and build come from
// the file name; versions 4 and 5 wrote "kind", "name", "version" and "url".
// A PyPI package from a Git repository ("git+https://…?tag=…#<commit>") is a
// Git dependency. Development-only packages are not marked: pixi expresses
// them as environments, not as a flag on a package.
type pixiLock struct{}

func (pixiLock) Type() string            { return "conda" }
func (pixiLock) Format() string          { return "pixi.lock" }
func (pixiLock) Detect(path string) bool { return baseName(path) == "pixi.lock" }

func (pixiLock) Parse(data []byte) (*Result, error) {
	m, err := readYAMLLock(data, "pixi.lock")
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errNotFormat("pixi.lock", "empty")
	}
	res := &Result{FormatVersion: yamlScalar(yamlGet(m, "version"))}
	packages := yamlGet(m, "packages")
	if res.FormatVersion == "" || packages == nil && yamlGet(m, "environments") == nil {
		return nil, errNotFormat("pixi.lock", "no version or no packages")
	}
	for _, p := range yamlSeq(packages) {
		if d, ok := pixiDependency(res, p); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
	}
	return res, nil
}

func pixiDependency(res *Result, p *yaml.Node) (Dependency, bool) {
	line := p.Line
	kind, loc := yamlScalar(yamlGet(p, "kind")), yamlScalar(yamlGet(p, "url"))
	if kind == "" {
		conda, pypi := yamlScalar(yamlGet(p, "conda")), yamlScalar(yamlGet(p, "pypi"))
		switch {
		case conda != "" && pypi != "":
			// pixi never writes both; its reader would take the conda file.
			res.warnf("line %d: a package record with both a conda and a PyPI location, left out", line)
			return Dependency{}, false
		case conda != "":
			kind, loc = "conda", conda
		case pypi != "":
			kind, loc = "pypi", pypi
		}
	}
	switch kind {
	case "conda":
		if !isHTTPURL(loc) {
			res.warnf("line %d: a conda package from a location that is not an HTTP URL", line)
			return Dependency{}, false
		}
		channel, file, ok := condaChannelFile(loc)
		if !ok {
			res.warnf("line %d: a URL that names no package file", line)
			return Dependency{}, false
		}
		name, version, _, _ := condaFileParts(fileNameOf(file))
		d := Dependency{Name: name, Version: version, Registry: channel, URL: cleanURL(loc), Line: line}
		for _, alg := range []string{"sha256", "md5"} {
			if dg, ok := hexDigest(alg, yamlScalar(yamlGet(p, alg)), file); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		if !validPackageName(d.Name) || !validVersion(d.Version) {
			res.warnf("line %d: a conda package without a usable name or version", line)
			return Dependency{}, false
		}
		return d, true
	case "pypi":
		d := Dependency{Type: "pip", Name: pyNormalize(yamlScalar(yamlGet(p, "name"))), Version: yamlScalar(yamlGet(p, "version")), Line: line}
		switch {
		case strings.HasPrefix(loc, "git+"):
			gs := parseGitURL(loc)
			d.Source, d.Registry, d.Revision = SourceGit, gs.repo, gs.revision
		case isHTTPURL(loc):
			d.URL = cleanURL(loc)
			if dg, ok := hexDigest("sha256", yamlScalar(yamlGet(p, "sha256")), fileNameOf(d.URL)); ok {
				d.Digests = append(d.Digests, dg)
			}
		default:
			res.warnf("line %d: %s: a PyPI package from a local path, not fetched", line, quoteName(d.Name))
			return Dependency{}, false
		}
		if !validPackageName(d.Name) || !validVersion(d.Version) {
			res.warnf("line %d: a PyPI package without a usable name or version", line)
			return Dependency{}, false
		}
		return d, true
	}
	res.warnf("line %d: a package record of a kind this parser does not read", line)
	return Dependency{}, false
}
