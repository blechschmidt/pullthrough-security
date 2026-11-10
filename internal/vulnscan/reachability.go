package vulnscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
)

// Reachability classifies whether a vulnerable component is reachable from the
// consuming artifact via static import analysis (Task 118, extended to Python and
// Java in Task 150). It is a three-valued attribute attached to every finding so
// unreachable vulnerabilities can be down-ranked or suppressed by policy instead
// of blocking.
//
// The analysis is deliberately conservative and sound in one direction: a
// finding is only ever marked Unreachable when the artifact's source was fully
// located and parsed AND the vulnerable module/package is provably not imported
// by the artifact's own first-party code (for Go it is a flattened transitive
// requirement the module does not import; for npm/Python/Java it is a declared
// dependency no analyzed source file references). Every ambiguous or incomplete
// case defaults to Unknown so missing analysis never silently clears a real
// vulnerability.
//
// Reachability is computed at import granularity from the consuming artifact's
// own packages. An Unreachable finding may still be exploitable through a direct
// dependency's code, which this analysis does not inspect; "unreachable"
// therefore means "not reachable from the artifact's own import graph", which is
// why the default policy only annotates (operators opt in to downgrade/suppress).
type Reachability string

const (
	// ReachabilityReachable means the vulnerable module/package is imported by the
	// artifact's own source (or is the artifact itself). Definitive.
	ReachabilityReachable Reachability = "reachable"
	// ReachabilityUnreachable means the artifact's source was fully analyzed and the
	// vulnerable module/package is not imported by any of the artifact's packages.
	ReachabilityUnreachable Reachability = "unreachable"
	// ReachabilityUnknown means the analysis was incomplete or ambiguous: no source
	// available, an unsupported ecosystem, an unparseable artifact, a dynamic import
	// that cannot be resolved statically, or a declared-direct dependency whose
	// import could not be confirmed. The conservative default.
	ReachabilityUnknown Reachability = "unknown"
)

// ReachabilityAction selects how the gate treats a finding proven Unreachable.
type ReachabilityAction string

const (
	// ReachActionAnnotate only records the reachability attribute (default). The
	// finding gates exactly as it would without reachability analysis.
	ReachActionAnnotate ReachabilityAction = "annotate"
	// ReachActionDowngrade lowers an unreachable finding's qualitative severity by
	// one bucket (critical→high→medium→low→none) for gating and counts. CVSS-based
	// gating is unaffected.
	ReachActionDowngrade ReachabilityAction = "downgrade"
	// ReachActionSuppress excludes an unreachable finding from gating entirely (it is
	// retained in the report for transparency, like a VEX not_affected suppression).
	ReachActionSuppress ReachabilityAction = "suppress"
)

// NormalizeReachabilityAction coerces a configured action string to a known
// ReachabilityAction, defaulting to annotate for empty/unrecognized values.
func NormalizeReachabilityAction(s string) ReachabilityAction {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "downgrade", "lower", "demote":
		return ReachActionDowngrade
	case "suppress", "ignore", "drop":
		return ReachActionSuppress
	default:
		return ReachActionAnnotate
	}
}

// downgradeSeverity lowers a severity by one qualitative bucket. Unknown and none
// collapse to none; a bucket already at the floor is unchanged.
func downgradeSeverity(s Severity) Severity {
	switch NormalizeSeverity(string(s)) {
	case SeverityCritical:
		return SeverityHigh
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	case SeverityLow, SeverityUnknown:
		return SeverityNone
	default:
		return SeverityNone
	}
}

// ecosystem families the reachability index distinguishes. Each is handled by its
// own analyzer and classify branch.
const (
	familyGo     = "go"
	familyNPM    = "npm"
	familyPython = "pip"
	familyJava   = "maven"
)

// reachabilityIndex is the static import analysis of one artifact's source,
// consulted once per finding to classify reachability. It is ecosystem-specific
// but exposes a single classify entry point.
type reachabilityIndex struct {
	// ecosystem is the canonical family: one of familyGo/familyNPM/familyPython/
	// familyJava, or the raw ecosystem name for an unsupported one.
	ecosystem string
	// analyzed is true when source was located and parsed. When false every
	// non-primary classification is Unknown.
	analyzed bool
	// reason explains an incomplete analysis, surfaced on Unknown classifications.
	reason string

	// importsObserved is true when at least one source file that could carry
	// import/require statements was parsed. The Unreachable verdict for a declared
	// dependency requires it: without any observed imports we cannot prove a
	// dependency is unused (Go's go.mod-only path is the sole documented exception).
	importsObserved bool

	// imported is the set of import references observed in the artifact's own
	// source: Go import paths (matched by module prefix), npm package names
	// (exact, lower-cased), Python top-level module names (lower-cased), or Java
	// package names (dotted, from import declarations).
	imported map[string]bool

	// provides is the set of modules/packages the artifact itself ships: Python
	// top-level modules (top_level.txt / package directories), Java packages (from
	// `package` declarations and .class directory paths). It makes a finding on the
	// artifact's own code reachable even when the primary-coordinate match missed
	// it (e.g. a version skew). Only ever widens reachability (the safe direction).
	provides map[string]bool

	// direct and indirect record declared dependencies and their manifest
	// classification. For Go these come from go.mod require directives (indirect =
	// the "// indirect" marker). For npm/Python/Java, declared dependencies populate
	// direct (these ecosystems do not flatten transitive deps into the manifest).
	direct   map[string]bool
	indirect map[string]bool

	// dynamic marks that the source contains a dynamic import/require/reflection
	// with a non-literal specifier (npm require(x), Python importlib.import_module,
	// Java Class.forName), so a declared-but-not-statically-imported dependency
	// cannot be proven unreachable.
	dynamic bool
}

// newReachabilityIndex allocates an empty index for an ecosystem.
func newReachabilityIndex(ecosystem string) *reachabilityIndex {
	return &reachabilityIndex{
		ecosystem: ecosystem,
		imported:  map[string]bool{},
		provides:  map[string]bool{},
		direct:    map[string]bool{},
		indirect:  map[string]bool{},
	}
}

// analyzeReachability builds a reachability index from an artifact's raw content
// for the supported ecosystems (Go module zips, npm tarballs, Python
// wheels/sdists, Java/Maven jars). An unsupported ecosystem or unparseable
// content yields a not-analyzed index whose every classification is Unknown.
func analyzeReachability(art Artifact, data []byte) *reachabilityIndex {
	eco := strings.ToLower(strings.TrimSpace(art.Ecosystem))
	switch eco {
	case "go", "golang", "gomod":
		return analyzeGoReachability(data)
	case "npm":
		return analyzeNPMReachability(data)
	case "pip", "pypi", "python":
		return analyzePythonReachability(data)
	case "maven", "java", "gradle":
		return analyzeJavaReachability(data)
	default:
		idx := newReachabilityIndex(eco)
		idx.reason = "reachability analysis is not supported for ecosystem " + orUnknownEco(eco)
		return idx
	}
}

// classify returns the reachability of the coordinate named by key (the finding's
// full package/module path) relative to the analyzed artifact. isPrimary marks a
// finding on the artifact itself. It never panics on a nil receiver.
//
// classify is the coordinate-only entry point retained for callers and tests that
// have no advisory-supplied import paths; classifyFinding is the richer form.
func (idx *reachabilityIndex) classify(key string, isPrimary bool) (Reachability, string) {
	return idx.classifyFinding(key, nil, isPrimary)
}

// classifyFinding classifies a finding using both its package coordinate (key)
// and the advisory's declared affected module/package import paths (affected,
// from OSV ecosystem_specific.imports), when available. affected refines the
// Python/Java match to the exact vulnerable module; it is ignored for Go/npm
// whose coordinate already is the import key.
func (idx *reachabilityIndex) classifyFinding(key string, affected []string, isPrimary bool) (Reachability, string) {
	// The artifact itself is trivially reachable — it is the consuming unit — even
	// when its source could not be analyzed.
	if isPrimary {
		return ReachabilityReachable, "the vulnerability is in the artifact itself"
	}
	if idx == nil {
		return ReachabilityUnknown, "reachability was not analyzed (re-scan from stored SBOM without artifact content)"
	}
	if !idx.analyzed {
		return ReachabilityUnknown, idx.reason
	}
	key = idx.normalizeKey(key)
	if key == "" {
		return ReachabilityUnknown, "the finding has no resolvable import path"
	}
	if idx.isImported(key, affected) {
		return ReachabilityReachable, "imported by the artifact's own source"
	}
	// Not statically imported by the artifact's own source.
	if idx.dynamic {
		return ReachabilityUnknown, "not statically imported, but the source uses a dynamic import/reflection (cannot prove unreachable)"
	}
	switch idx.ecosystem {
	case familyGo:
		// Go: the direct/indirect classification disambiguates.
		if idx.direct[key] {
			// go.mod declares this a direct dependency — the module's packages import it
			// somewhere — yet no import was observed, likely a build-tag-guarded or
			// generated import the parser did not see. Be conservative.
			return ReachabilityUnknown, "declared a direct dependency but no import was observed in the analyzed sources"
		}
		if idx.indirect[key] {
			return ReachabilityUnreachable, "transitive (indirect) dependency not imported by the artifact's own packages"
		}
		return ReachabilityUnknown, "the coordinate is not a declared dependency of the analyzed artifact"
	default:
		// npm/Python/Java: a declared dependency has no transitive flattening, so one
		// that no analyzed source file imports is genuinely unused by this artifact —
		// but only once we have actually observed the artifact's imports. Without
		// parsed source we cannot prove non-use, so stay Unknown.
		if idx.direct[key] {
			if !idx.importsObserved {
				return ReachabilityUnknown, "declared dependency, but no source files were analyzed to confirm it is unused"
			}
			return ReachabilityUnreachable, "declared dependency not imported by any of the artifact's source files"
		}
		return ReachabilityUnknown, "the coordinate is not a declared dependency of the analyzed artifact"
	}
}

// normalizeKey canonicalizes a finding coordinate per ecosystem: npm package
// names are lower-cased; Python distribution names are PyPI-normalized
// (lower-case, runs of -_. collapsed to a single -); Go module paths and Java
// groupId:artifactId coordinates are left as-is (case-sensitive).
func (idx *reachabilityIndex) normalizeKey(key string) string {
	key = strings.TrimSpace(key)
	switch idx.ecosystem {
	case familyNPM:
		return strings.ToLower(key)
	case familyPython:
		return normalizePyPIName(key)
	default:
		return key
	}
}

// isImported reports whether key (optionally refined by the advisory's affected
// import paths) is referenced by the artifact's source.
func (idx *reachabilityIndex) isImported(key string, affected []string) bool {
	switch idx.ecosystem {
	case familyNPM:
		return idx.imported[key]
	case familyGo:
		return idx.isImportedGo(key)
	case familyPython:
		return idx.isImportedPython(key, affected)
	case familyJava:
		return idx.isImportedJava(key, affected)
	default:
		return idx.imported[key]
	}
}

// isImportedGo matches a Go module path against observed import paths by exact
// match or module prefix (an import of a sub-package of the module counts as
// importing the module).
func (idx *reachabilityIndex) isImportedGo(key string) bool {
	if idx.imported[key] {
		return true
	}
	prefix := key + "/"
	for imp := range idx.imported {
		if strings.HasPrefix(imp, prefix) {
			return true
		}
	}
	return false
}

// --- Go analysis ------------------------------------------------------------

// analyzeGoReachability parses a Go module zip: go.mod for direct/indirect
// requires and every .go file for its import paths.
func analyzeGoReachability(data []byte) *reachabilityIndex {
	idx := newReachabilityIndex(familyGo)
	if len(data) == 0 {
		idx.reason = "no artifact content available for reachability analysis"
		return idx
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		idx.reason = "artifact is not a readable Go module zip"
		return idx
	}
	var sawGoMod, sawSource bool
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, "./")
		switch {
		case name == "go.mod" || strings.HasSuffix(name, "/go.mod"):
			if b, err := readZipEntry(f, maxManifestBytes); err == nil {
				idx.loadGoMod(b)
				sawGoMod = true
			}
		case strings.HasSuffix(name, ".go"):
			if b, err := readZipEntry(f, maxManifestBytes); err == nil {
				for _, imp := range parseGoImports(b) {
					idx.imported[imp] = true
				}
				sawSource = true
			}
		}
	}
	if !sawGoMod && !sawSource {
		idx.reason = "no go.mod or Go source files found in the artifact"
		return idx
	}
	idx.analyzed = true
	idx.importsObserved = sawSource
	if !sawSource {
		// go.mod's direct/indirect classification is authoritative on its own (go mod
		// tidy maintains it), so analysis is still usable without source files.
		idx.reason = "go.mod parsed but no source files were found; using the module's direct/indirect classification"
	}
	return idx
}

// loadGoMod records each require directive's direct/indirect classification.
func (idx *reachabilityIndex) loadGoMod(gomod []byte) {
	for _, r := range parseGoRequiresMeta(gomod) {
		if r.indirect {
			idx.indirect[r.path] = true
		} else {
			idx.direct[r.path] = true
		}
	}
}

// parseGoImports returns the import paths declared by a Go source file. It uses
// the standard library parser in imports-only mode so partial/invalid function
// bodies never defeat it and the result is deterministic. A file that fails to
// parse even its import block contributes nothing.
func parseGoImports(src []byte) []string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", src, parser.ImportsOnly)
	if err != nil || file == nil {
		return nil
	}
	out := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		if imp == nil || imp.Path == nil {
			continue
		}
		p := strings.Trim(imp.Path.Value, "`\"")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// --- npm analysis -----------------------------------------------------------

// npmSourceExts are the file extensions scanned for import/require references.
var npmSourceExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true,
	".ts": true, ".mts": true, ".cts": true,
	".jsx": true, ".tsx": true,
}

// analyzeNPMReachability parses an npm tarball (gzip+tar): package.json for the
// declared dependency set and every JS/TS source file for its import/require
// specifiers.
func analyzeNPMReachability(data []byte) *reachabilityIndex {
	idx := newReachabilityIndex(familyNPM)
	if len(data) == 0 {
		idx.reason = "no artifact content available for reachability analysis"
		return idx
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		idx.reason = "artifact is not a readable npm tarball"
		return idx
	}
	defer gz.Close()

	var sawManifest, sawSource bool
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		// npm tarballs root every entry under "package/". Ignore bundled deps.
		if strings.Contains(name, "/node_modules/") {
			continue
		}
		base := name
		if strings.HasPrefix(base, "package/") {
			base = strings.TrimPrefix(base, "package/")
		}
		switch {
		case base == "package.json":
			if b, err := readCapped(tr, maxManifestBytes); err == nil {
				idx.loadPackageJSON(b)
				sawManifest = true
			}
		case npmSourceExts[strings.ToLower(ext(name))]:
			if b, err := readCapped(tr, maxManifestBytes); err == nil {
				idx.scanNPMSource(b)
				sawSource = true
			}
		}
	}
	if !sawManifest && !sawSource {
		idx.reason = "no package.json or source files found in the artifact"
		return idx
	}
	idx.analyzed = true
	idx.importsObserved = sawSource
	if !sawSource {
		idx.reason = "package.json parsed but no source files were found"
	}
	return idx
}

// loadPackageJSON records the package's declared dependency names (runtime,
// optional, and peer) as the direct dependency set.
func (idx *reachabilityIndex) loadPackageJSON(data []byte) {
	var manifest struct {
		Dependencies         map[string]json.RawMessage `json:"dependencies"`
		OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
		PeerDependencies     map[string]json.RawMessage `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return
	}
	for _, deps := range []map[string]json.RawMessage{
		manifest.Dependencies, manifest.OptionalDependencies, manifest.PeerDependencies,
	} {
		for name := range deps {
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				idx.direct[name] = true
			}
		}
	}
}

// npmRequireRe matches a require()/import()/import-from/export-from with a
// string-literal specifier, capturing the specifier.
var npmRequireRe = regexp.MustCompile(`(?:require|import)\s*\(\s*['"]([^'"]+)['"]|(?:import|export)[^;'"]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]`)

// npmDynamicRe matches a require()/import() whose first argument is not a string
// literal (a variable, template literal, or expression) — a dynamic import that
// prevents proving a dependency unreachable.
var npmDynamicRe = regexp.MustCompile(`(?:require|import)\s*\(\s*[^'")\s]`)

// scanNPMSource extracts static import specifiers from a JS/TS source file and
// flags any dynamic import/require.
func (idx *reachabilityIndex) scanNPMSource(data []byte) {
	src := string(data)
	for _, m := range npmRequireRe.FindAllStringSubmatch(src, -1) {
		spec := m[1]
		if spec == "" {
			spec = m[2]
		}
		if spec == "" {
			spec = m[3]
		}
		if name, ok := npmPackageName(spec); ok {
			idx.imported[name] = true
		}
	}
	if npmDynamicRe.MatchString(src) {
		idx.dynamic = true
	}
}

// npmPackageName reduces an import specifier to its package name: "@scope/pkg"
// for a scoped specifier, the first path segment otherwise. Relative, absolute,
// and node: builtin specifiers return ok=false.
func npmPackageName(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") {
		return "", false
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) >= 2 && parts[0] != "@" && parts[1] != "" {
			return strings.ToLower(parts[0] + "/" + parts[1]), true
		}
		return "", false
	}
	if parts[0] == "" {
		return "", false
	}
	return strings.ToLower(parts[0]), true
}

// --- Python analysis --------------------------------------------------------

// pySourceExts are the file extensions scanned for import statements.
var pySourceExts = map[string]bool{".py": true, ".pyi": true}

// analyzePythonReachability parses a Python wheel (a zip) or sdist (a gzip+tar).
// It collects the declared dependency set (from core-metadata Requires-Dist,
// egg-info requires.txt, requirements.txt, setup.py, and pyproject.toml), the
// top-level modules the artifact itself provides (top_level.txt and package
// directories), and every import statement in the artifact's .py source.
func analyzePythonReachability(data []byte) *reachabilityIndex {
	idx := newReachabilityIndex(familyPython)
	if len(data) == 0 {
		idx.reason = "no artifact content available for reachability analysis"
		return idx
	}
	var sawSource, sawManifest bool
	consume := func(name string, body []byte) {
		src, manifest := idx.consumePythonEntry(name, body)
		sawSource = sawSource || src
		sawManifest = sawManifest || manifest
	}
	// Wheels are zips; sdists are gzip+tar. Try zip first, then tar.gz.
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			if b, err := readZipEntry(f, maxManifestBytes); err == nil {
				consume(strings.TrimPrefix(f.Name, "./"), b)
			}
		}
	} else if gz, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err != nil {
				break
			}
			if hdr.Typeflag != tar.TypeReg {
				continue
			}
			if b, err := readCapped(tr, maxManifestBytes); err == nil {
				consume(strings.TrimPrefix(hdr.Name, "./"), b)
			}
		}
	} else {
		idx.reason = "artifact is not a readable Python wheel or sdist"
		return idx
	}

	if !sawSource && !sawManifest && len(idx.provides) == 0 {
		idx.reason = "no Python source, metadata, or dependency manifest found in the artifact"
		return idx
	}
	idx.analyzed = true
	idx.importsObserved = sawSource
	if !sawSource {
		idx.reason = "Python metadata parsed but no source files were found to confirm imports"
	}
	return idx
}

// consumePythonEntry routes one archive entry to the appropriate parser and
// reports whether it contributed source imports and/or dependency metadata.
func (idx *reachabilityIndex) consumePythonEntry(name string, body []byte) (source, manifest bool) {
	// Ignore bundled/vendored dependencies and test trees so we analyze only the
	// artifact's own first-party code.
	lower := strings.ToLower(name)
	if strings.Contains(lower, "site-packages/") || strings.Contains(lower, "/vendor/") {
		return false, false
	}
	base := name
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	switch {
	case pySourceExts[strings.ToLower(ext(name))]:
		idx.scanPythonSource(body)
		idx.addPythonProvidesFromPath(name)
		return true, false
	case base == "top_level.txt" && (strings.Contains(name, ".dist-info/") || strings.Contains(name, ".egg-info/")):
		for _, line := range strings.Split(string(body), "\n") {
			if m := strings.ToLower(strings.TrimSpace(line)); m != "" {
				idx.provides[firstPathSegment(m)] = true
			}
		}
		return false, true
	case base == "METADATA" && strings.Contains(name, ".dist-info/"):
		idx.loadPythonCoreMetadata(body)
		return false, true
	case base == "PKG-INFO":
		idx.loadPythonCoreMetadata(body)
		return false, true
	case base == "requires.txt" && strings.Contains(name, ".egg-info/"):
		idx.loadPythonRequiresTxt(body)
		return false, true
	case base == "requirements.txt":
		idx.loadPythonRequiresTxt(body)
		return false, true
	case base == "pyproject.toml":
		idx.loadPyProjectDeps(body)
		return false, true
	case base == "setup.py":
		idx.loadSetupPyDeps(body)
		return false, true
	default:
		return false, false
	}
}

// addPythonProvidesFromPath records the top-level package a source file belongs to
// (the first path segment under the archive/version root), so the artifact's own
// modules count as reachable.
func (idx *reachabilityIndex) addPythonProvidesFromPath(name string) {
	parts := strings.Split(name, "/")
	// sdists nest under "<name>-<version>/"; wheels place packages at the root.
	start := 0
	if len(parts) > 1 && strings.Contains(parts[0], "-") {
		start = 1
	}
	if start >= len(parts) {
		return
	}
	seg := strings.ToLower(parts[start])
	if seg == "" || strings.HasSuffix(seg, ".py") || strings.HasSuffix(seg, ".pyi") ||
		strings.HasSuffix(seg, ".dist-info") || strings.HasSuffix(seg, ".egg-info") {
		return
	}
	idx.provides[seg] = true
}

// pyImportRe matches top-level `import a, b.c` and `from a.b import c` statements,
// capturing the module list / dotted module. Relative imports (leading dot) are
// handled by the caller.
var (
	pyImportRe     = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([\w., \t]+)`)
	pyFromRe       = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+(\.*[\w.]+)[ \t]+import\b`)
	pyDynamicRe    = regexp.MustCompile(`(?:importlib\.import_module|__import__)\s*\(\s*[^'")\s]`)
	pyImportSepRe  = regexp.MustCompile(`[ \t]+as[ \t]+[\w]+`)
	pyImportListRe = regexp.MustCompile(`[,]`)
)

// scanPythonSource extracts imported top-level module names from a .py file and
// flags dynamic imports (importlib.import_module / __import__ with a non-literal).
func (idx *reachabilityIndex) scanPythonSource(data []byte) {
	src := string(data)
	for _, m := range pyImportRe.FindAllStringSubmatch(src, -1) {
		// "import a.b as x, c" -> each comma-separated clause, drop "as alias".
		clause := pyImportSepRe.ReplaceAllString(m[1], "")
		for _, item := range pyImportListRe.Split(clause, -1) {
			mod := strings.TrimSpace(item)
			if top := pythonTopModule(mod); top != "" {
				idx.imported[top] = true
			}
		}
	}
	for _, m := range pyFromRe.FindAllStringSubmatch(src, -1) {
		mod := strings.TrimSpace(m[1])
		if strings.HasPrefix(mod, ".") {
			continue // intra-package relative import; not a third-party module
		}
		if top := pythonTopModule(mod); top != "" {
			idx.imported[top] = true
		}
	}
	if pyDynamicRe.MatchString(src) {
		idx.dynamic = true
	}
}

// pythonTopModule returns the lower-cased first dotted component of a module path,
// or "" if none/relative.
func pythonTopModule(mod string) string {
	mod = strings.TrimSpace(mod)
	if mod == "" || strings.HasPrefix(mod, ".") {
		return ""
	}
	if i := strings.IndexByte(mod, '.'); i >= 0 {
		mod = mod[:i]
	}
	return strings.ToLower(strings.TrimSpace(mod))
}

// loadPythonCoreMetadata reads PEP 566 core metadata (wheel METADATA / sdist
// PKG-INFO) and records each Requires-Dist distribution as a direct dependency.
func (idx *reachabilityIndex) loadPythonCoreMetadata(meta []byte) {
	for _, raw := range strings.Split(string(meta), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			break // headers end at the first blank line (long description follows)
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "requires-dist") {
			continue
		}
		if name := pythonRequirementName(val); name != "" {
			idx.direct[name] = true
		}
	}
}

// loadPythonRequiresTxt parses a pip requirements.txt / egg-info requires.txt:
// one requirement per line, with "[extra]" section markers and comments skipped.
func (idx *reachabilityIndex) loadPythonRequiresTxt(data []byte) {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") ||
			strings.HasPrefix(line, "-") {
			continue
		}
		if name := pythonRequirementName(line); name != "" {
			idx.direct[name] = true
		}
	}
}

// pyProjectDepRe captures a single dependency string inside a TOML array (either
// the PEP 621 [project].dependencies list or a Poetry inline table key).
var pyProjectDepLineRe = regexp.MustCompile(`["']([A-Za-z0-9][A-Za-z0-9._-]*)[^"']*["']`)

// loadPyProjectDeps best-effort parses a pyproject.toml for PEP 621
// [project].dependencies (and optional-dependencies) entries. It is intentionally
// tolerant: a parse miss contributes nothing (defaulting findings to Unknown).
func (idx *reachabilityIndex) loadPyProjectDeps(data []byte) {
	text := string(data)
	// Extract the dependencies array bodies and scan each quoted requirement.
	for _, body := range tomlArrayBodies(text, "dependencies") {
		for _, m := range pyProjectDepLineRe.FindAllStringSubmatch(body, -1) {
			if name := normalizePyPIName(m[1]); name != "" {
				idx.direct[name] = true
			}
		}
	}
}

// tomlArrayBodies returns the comma-separated bodies of every `<key> = [ ... ]`
// array assignment whose key ends with the given suffix (so it matches both
// "dependencies" and "optional-dependencies" group tables flattened by the
// Poetry/PEP 621 forms). It is a lightweight scan, not a full TOML parser.
func tomlArrayBodies(text, keySuffix string) []string {
	var out []string
	idx := 0
	for {
		pos := strings.Index(text[idx:], keySuffix)
		if pos < 0 {
			break
		}
		at := idx + pos
		idx = at + len(keySuffix)
		// Require the key to be followed (after optional whitespace/subkey) by '= ['.
		rest := strings.TrimLeft(text[idx:], " \t")
		// Allow "dependencies = [" and "optional-dependencies.foo = [" shapes by
		// skipping to the next '=' on the same logical line.
		eq := strings.IndexByte(rest, '=')
		nl := strings.IndexByte(rest, '\n')
		if eq < 0 || (nl >= 0 && nl < eq) {
			continue
		}
		after := strings.TrimLeft(rest[eq+1:], " \t")
		if !strings.HasPrefix(after, "[") {
			continue
		}
		if close := strings.IndexByte(after, ']'); close >= 0 {
			out = append(out, after[1:close])
		}
	}
	return out
}

// setupPyRequiresRe captures the install_requires=[...] list body in a setup.py.
var setupPyRequiresRe = regexp.MustCompile(`install_requires\s*=\s*\[([^\]]*)\]`)

// loadSetupPyDeps best-effort extracts install_requires entries from a setup.py.
func (idx *reachabilityIndex) loadSetupPyDeps(data []byte) {
	m := setupPyRequiresRe.FindStringSubmatch(string(data))
	if m == nil {
		return
	}
	for _, dep := range pyProjectDepLineRe.FindAllStringSubmatch(m[1], -1) {
		if name := normalizePyPIName(dep[1]); name != "" {
			idx.direct[name] = true
		}
	}
}

// pythonRequirementName extracts and normalizes the distribution name from a
// requirement specifier ("Flask (>=1.0)", "requests>=2; python_version<'3'",
// "foo[extra]==1.0"). Returns "" when no name is present.
func pythonRequirementName(spec string) string {
	spec = strings.TrimSpace(spec)
	// Trim an environment marker ("; ...") and any version/extra suffix.
	if i := strings.IndexByte(spec, ';'); i >= 0 {
		spec = spec[:i]
	}
	spec = strings.TrimSpace(spec)
	// The name is the leading run of name characters.
	end := 0
	for end < len(spec) {
		c := spec[end]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' {
			end++
			continue
		}
		break
	}
	return normalizePyPIName(spec[:end])
}

// normalizePyPIName applies PEP 503 name normalization: lower-case and collapse
// any run of "-", "_", or "." to a single "-".
var pyNameSepRe = regexp.MustCompile(`[-_.]+`)

func normalizePyPIName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	return pyNameSepRe.ReplaceAllString(name, "-")
}

// pythonModuleCandidates returns the plausible import module names for a
// PEP-503-normalized distribution name. The import module is overwhelmingly the
// distribution name with separators turned into underscores (or removed); the
// mapping is not guaranteed (e.g. PyYAML→yaml), which is why a declared dependency
// whose module is not found is only ever marked Unreachable, never when the
// mapping is ambiguous enough to risk a false clear.
func pythonModuleCandidates(normDist string) []string {
	if normDist == "" {
		return nil
	}
	underscore := strings.ReplaceAll(normDist, "-", "_")
	collapsed := strings.ReplaceAll(normDist, "-", "")
	out := []string{underscore}
	if collapsed != underscore {
		out = append(out, collapsed)
	}
	return out
}

// isImportedPython reports whether the vulnerable Python distribution (key, a
// PEP-503-normalized name) or any advisory-declared affected module is imported
// by (or provided by) the artifact's own source.
func (idx *reachabilityIndex) isImportedPython(key string, affected []string) bool {
	// Advisory-declared affected modules are the most precise signal: match them
	// directly against the observed imports/provides.
	for _, a := range affected {
		if top := pythonTopModule(a); top != "" && idx.pythonHasModule(top) {
			return true
		}
	}
	for _, cand := range pythonModuleCandidates(key) {
		if idx.pythonHasModule(cand) {
			return true
		}
	}
	return false
}

// pythonHasModule reports whether a top-level module is imported by or provided by
// the artifact.
func (idx *reachabilityIndex) pythonHasModule(mod string) bool {
	return idx.imported[mod] || idx.provides[mod]
}

// --- Java / Maven analysis --------------------------------------------------

// analyzeJavaReachability parses a Java artifact jar (a zip): source .java files
// for their `package`/`import` declarations, compiled .class entries for the
// packages the artifact itself provides, and the embedded Maven pom.xml for the
// declared dependency coordinates.
func analyzeJavaReachability(data []byte) *reachabilityIndex {
	idx := newReachabilityIndex(familyJava)
	if len(data) == 0 {
		idx.reason = "no artifact content available for reachability analysis"
		return idx
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		idx.reason = "artifact is not a readable Java/Maven jar"
		return idx
	}
	var sawSource, sawClasses, sawManifest bool
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.TrimPrefix(f.Name, "./")
		base := name
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		switch {
		case strings.HasSuffix(name, ".java"):
			if b, err := readZipEntry(f, maxManifestBytes); err == nil {
				idx.scanJavaSource(b)
				sawSource = true
			}
		case strings.HasSuffix(name, ".class"):
			if pkg := javaPackageFromClassPath(name); pkg != "" {
				idx.provides[pkg] = true
				sawClasses = true
			}
		case base == "pom.xml":
			if b, err := readZipEntry(f, maxManifestBytes); err == nil {
				idx.loadMavenPOM(b)
				sawManifest = true
			}
		}
	}
	if !sawSource && !sawClasses && !sawManifest {
		idx.reason = "no Java source, class files, or pom.xml found in the artifact"
		return idx
	}
	idx.analyzed = true
	idx.importsObserved = sawSource
	if !sawSource {
		idx.reason = "Java metadata/bytecode present but no source files were found to confirm imports"
	}
	return idx
}

var (
	javaPackageRe   = regexp.MustCompile(`(?m)^[ \t]*package[ \t]+([\w.]+)[ \t]*;`)
	javaImportRe    = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+(?:static[ \t]+)?([\w.]+(?:\.\*)?)[ \t]*;`)
	javaReflectRe   = regexp.MustCompile(`(?:Class\.forName|\.loadClass)\s*\(\s*[^"')\s]`)
	javaDotStarTrim = ".*"
)

// scanJavaSource records the package a .java file declares (a provided package)
// and every package it imports, and flags reflective class loading.
func (idx *reachabilityIndex) scanJavaSource(data []byte) {
	src := string(data)
	for _, m := range javaPackageRe.FindAllStringSubmatch(src, -1) {
		if pkg := strings.TrimSpace(m[1]); pkg != "" {
			idx.provides[pkg] = true
		}
	}
	for _, m := range javaImportRe.FindAllStringSubmatch(src, -1) {
		imp := strings.TrimSpace(m[1])
		imp = strings.TrimSuffix(imp, javaDotStarTrim)
		if pkg := javaImportPackage(imp); pkg != "" {
			idx.imported[pkg] = true
		}
	}
	if javaReflectRe.MatchString(src) {
		idx.dynamic = true
	}
}

// javaImportPackage reduces an import target to its package by dropping the
// trailing type name. "org.apache.commons.lang3.StringUtils" -> the type's
// package "org.apache.commons.lang3"; a wildcard import "org.apache.commons.lang3"
// (the ".*" already trimmed) is already a package. The heuristic treats a final
// segment starting with an upper-case letter as a type name to strip.
func javaImportPackage(imp string) string {
	imp = strings.TrimSpace(imp)
	if imp == "" {
		return ""
	}
	last := imp
	if i := strings.LastIndexByte(imp, '.'); i >= 0 {
		last = imp[i+1:]
		if last != "" && last[0] >= 'A' && last[0] <= 'Z' {
			return imp[:i]
		}
	}
	return imp
}

// javaPackageFromClassPath converts a .class entry path to its Java package,
// skipping JVM/module metadata. "org/apache/commons/lang3/StringUtils.class" ->
// "org.apache.commons.lang3".
func javaPackageFromClassPath(name string) string {
	if strings.HasPrefix(name, "META-INF/") || strings.HasPrefix(name, "module-info") ||
		strings.Contains(name, "/module-info.class") {
		return ""
	}
	dir := name
	if i := strings.LastIndexByte(dir, '/'); i >= 0 {
		dir = dir[:i]
	} else {
		return "" // default-package class; no package to record
	}
	return strings.ReplaceAll(dir, "/", ".")
}

// mavenDepRe captures <groupId> and <artifactId> inside each <dependency> block of
// a pom.xml. It tolerates attributes and whitespace; a miss contributes nothing.
var (
	mavenDepBlockRe  = regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)
	mavenGroupRe     = regexp.MustCompile(`<groupId>\s*([^<\s]+)\s*</groupId>`)
	mavenArtifactRe  = regexp.MustCompile(`<artifactId>\s*([^<\s]+)\s*</artifactId>`)
	mavenPropertyRef = regexp.MustCompile(`\$\{[^}]*\}`)
)

// loadMavenPOM records each <dependency>'s groupId:artifactId coordinate as a
// declared direct dependency.
func (idx *reachabilityIndex) loadMavenPOM(data []byte) {
	for _, block := range mavenDepBlockRe.FindAllStringSubmatch(string(data), -1) {
		g := firstSubmatch(mavenGroupRe, block[1])
		a := firstSubmatch(mavenArtifactRe, block[1])
		// Skip unresolved property placeholders (e.g. ${project.groupId}); we cannot
		// key a dependency on an unexpanded variable.
		if g == "" || a == "" || mavenPropertyRef.MatchString(g) || mavenPropertyRef.MatchString(a) {
			continue
		}
		idx.direct[g+":"+a] = true
	}
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// isImportedJava reports whether the vulnerable Maven coordinate (key,
// "groupId:artifactId") is imported by the artifact. It matches the advisory's
// declared affected Java packages when present, otherwise the dependency's groupId
// namespace, against the packages the artifact imports or provides. groupId
// matching is intentionally generous (it may over-report reachable), which is the
// safe direction — reachability never clears a vulnerability by being generous.
func (idx *reachabilityIndex) isImportedJava(key string, affected []string) bool {
	candidates := affected
	if len(candidates) == 0 {
		if g := mavenGroupID(key); g != "" {
			candidates = []string{g}
		}
	}
	if len(candidates) == 0 {
		return false
	}
	for pkg := range idx.imported {
		if javaPackageMatches(pkg, candidates) {
			return true
		}
	}
	for pkg := range idx.provides {
		if javaPackageMatches(pkg, candidates) {
			return true
		}
	}
	return false
}

// javaPackageMatches reports whether pkg lies within any candidate namespace
// (equal, or a dotted sub-package of it).
func javaPackageMatches(pkg string, candidates []string) bool {
	for _, c := range candidates {
		c = strings.TrimSuffix(strings.TrimSpace(c), javaDotStarTrim)
		if c == "" {
			continue
		}
		if pkg == c || strings.HasPrefix(pkg, c+".") {
			return true
		}
	}
	return false
}

// mavenGroupID returns the groupId of a "groupId:artifactId" coordinate, which by
// convention is the reverse-domain root of the artifact's Java packages.
func mavenGroupID(coord string) string {
	coord = strings.TrimSpace(coord)
	if i := strings.IndexByte(coord, ':'); i >= 0 {
		return strings.TrimSpace(coord[:i])
	}
	return ""
}

// --- helpers ----------------------------------------------------------------

// readZipEntry opens a zip entry and reads up to max bytes.
func readZipEntry(f *zip.File, max int) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return readCapped(rc, max)
}

// ext returns the lower-case file extension including the dot, or "" if none.
func ext(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 && i > strings.LastIndexByte(name, '/') {
		return name[i:]
	}
	return ""
}

// firstPathSegment returns the first "/"-delimited segment of a path.
func firstPathSegment(p string) string {
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}

func orUnknownEco(eco string) string {
	if strings.TrimSpace(eco) == "" {
		return "(unknown)"
	}
	return eco
}
