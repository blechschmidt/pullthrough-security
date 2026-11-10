package installhooks

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
)

// Extraction bounds. Install-hook bearing files are tiny (a package.json, a
// setup.py, a build.rs); these caps keep a hostile or accidentally-huge archive
// from exhausting memory while still reading every realistic hook in full.
const (
	maxHookFileBytes = 1 << 20   // 1 MiB per scanned file
	maxTotalBytes    = 64 << 20  // 64 MiB of archive read overall
	maxTarEntries    = 20000     // entry-count guard against tar bombs
	maxHookScript    = 256 << 10 // 256 KiB of scanned script per hook
	// maxVsixBytes bounds how much of a .vsix (a zip) is buffered to read its
	// central directory. A VS Code extension archive must be buffered to locate
	// its manifest (the zip directory lives at the end of the stream); an archive
	// exceeding this cap fails open (served unscanned) rather than exhausting
	// memory. Most extensions are far smaller.
	maxVsixBytes = 96 << 20 // 96 MiB
)

// errTruncated is a sentinel signalling extraction hit a bound; it is reported
// as Report.Truncated, not as a hard error.
var errTruncated = errors.New("installhooks: extraction truncated at size/entry bound")

// supportedEcosystem reports whether the gate understands an ecosystem's
// artifact format and it has install-time hooks worth scanning.
func supportedEcosystem(eco string) bool {
	switch canonEco(eco) {
	case "npm", "pip", "cargo", "rubygems", "openvsx":
		return true
	default:
		return false
	}
}

// applicableArtifact reports whether an artifact of a supported ecosystem is a
// form that actually carries install hooks. A Python wheel (.whl) is a zip that
// runs no install-time code, so it is skipped entirely rather than recorded as a
// clean scan.
func applicableArtifact(art Artifact) bool {
	if canonEco(art.Ecosystem) == "pip" && isWheel(art) {
		return false
	}
	return true
}

func canonEco(eco string) string {
	e := strings.ToLower(strings.TrimSpace(eco))
	switch e {
	case "pypi", "python":
		return "pip"
	case "gem", "gems", "ruby":
		return "rubygems"
	case "crates", "crate", "rust":
		return "cargo"
	case "node", "nodejs":
		return "npm"
	case "vscode", "vsix", "ovsx", "open-vsx", "openvsx":
		return "openvsx"
	default:
		return e
	}
}

// extractHooks dispatches to the per-ecosystem parser. It returns the discovered
// hooks, whether extraction was truncated, and a non-nil error only for an
// unreadable archive (which the caller treats as fail-open).
func extractHooks(art Artifact, r io.Reader) (hooks []Hook, truncated bool, err error) {
	switch canonEco(art.Ecosystem) {
	case "npm":
		return extractNPM(r)
	case "pip":
		return extractPython(art, r)
	case "cargo":
		return extractCargo(r)
	case "rubygems":
		return extractRubyGems(r)
	case "openvsx":
		return extractOpenVSX(r)
	default:
		return nil, false, nil
	}
}

// collected is one file read out of an archive.
type collected struct {
	name string
	data []byte
}

// readTar walks a (possibly gzip/bzip2-compressed) tar stream, collecting files
// whose path satisfies want, each bounded to maxHookFileBytes. It enforces the
// overall byte and entry-count bounds, signalling truncation rather than
// erroring. files are returned in archive order.
func readTar(r io.Reader, compressed bool, want func(name string) bool) (files []collected, truncated bool, err error) {
	var src io.Reader = io.LimitReader(r, maxTotalBytes+1)
	if compressed {
		dr, derr := decompress(src)
		if derr != nil {
			return nil, false, derr
		}
		src = dr
	}
	tr := tar.NewReader(src)
	entries := 0
	for {
		hdr, herr := tr.Next()
		if herr == io.EOF {
			break
		}
		if herr != nil {
			// A clean-so-far stream that fails mid-way still yields what we read; a
			// header error on the very first entry is a real "not a tar" error.
			if entries == 0 {
				return nil, truncated, herr
			}
			break
		}
		entries++
		if entries > maxTarEntries {
			truncated = true
			break
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if !want(name) {
			continue
		}
		data, n, terr := readBounded(tr, maxHookFileBytes)
		if terr != nil {
			return files, truncated, terr
		}
		if n >= maxHookFileBytes {
			truncated = true
		}
		files = append(files, collected{name: name, data: data})
	}
	return files, truncated, nil
}

// decompress detects gzip (and bzip2 by trying gzip first) for a tar stream. The
// caller knows the format for most ecosystems, but npm/pip/cargo all ship gzip.
func decompress(r io.Reader) (io.Reader, error) {
	// Peek the first two bytes to choose a decompressor without consuming them.
	head := make([]byte, 2)
	n, _ := io.ReadFull(r, head)
	head = head[:n]
	combined := io.MultiReader(bytes.NewReader(head), r)
	switch {
	case n >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		return gzip.NewReader(combined)
	case n >= 2 && head[0] == 'B' && head[1] == 'Z':
		return bzip2.NewReader(combined), nil
	default:
		// Not compressed (or unknown): treat as a raw tar.
		return combined, nil
	}
}

// readBounded reads up to max bytes from r, returning the data and the number of
// bytes read. Reading exactly max signals possible truncation to the caller.
func readBounded(r io.Reader, max int) ([]byte, int, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(max)))
	if err != nil {
		return nil, len(data), err
	}
	return data, len(data), nil
}

// --- npm ---------------------------------------------------------------------

// npmLifecycle is the set of npm lifecycle script names that run automatically
// around install (the highest-risk hooks), plus the publish/pack hooks that also
// execute on the consumer side in some workflows. preinstall/install/postinstall
// are the canonical install-time backdoor vectors.
var npmLifecycle = []string{
	"preinstall", "install", "postinstall",
	"preuninstall", "postuninstall",
	"prepare", "prepublish", "prepublishOnly", "prepack", "postpack",
}

func extractNPM(r io.Reader) ([]Hook, bool, error) {
	// npm tarballs gzip a tar whose entries live under "package/".
	files, truncated, err := readTar(r, true, func(name string) bool {
		return path.Base(name) == "package.json"
	})
	if err != nil {
		return nil, truncated, err
	}
	// Prefer the canonical top-level package/package.json; fall back to the
	// shallowest package.json found.
	var manifest []byte
	bestDepth := 1 << 30
	for _, f := range files {
		if f.name == "package/package.json" {
			manifest = f.data
			break
		}
		if d := strings.Count(f.name, "/"); d < bestDepth {
			bestDepth = d
			manifest = f.data
		}
	}
	if manifest == nil {
		return nil, truncated, nil
	}
	scripts, perr := ParsePackageJSONScripts(manifest)
	if perr != nil {
		return nil, truncated, nil // a malformed manifest is not our error to raise
	}
	var hooks []Hook
	for _, name := range npmLifecycle {
		cmd, ok := scripts[name]
		if !ok || strings.TrimSpace(cmd) == "" {
			continue
		}
		hooks = append(hooks, Hook{
			Ecosystem: "npm",
			Kind:      name,
			Label:     "npm:" + name,
			File:      "package/package.json",
			Script:    boundScript(cmd),
		})
	}
	return hooks, truncated, nil
}

// ParsePackageJSONScripts extracts the "scripts" object from an npm
// package.json. It is a pure, fuzz-friendly parser: it tolerates arbitrary
// surrounding fields and returns an empty map (not an error) for a manifest
// without scripts.
func ParsePackageJSONScripts(data []byte) (map[string]string, error) {
	var doc struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc.Scripts))
	for k, raw := range doc.Scripts {
		// A script value is normally a string; tolerate non-string values by
		// rendering them verbatim so an obfuscated array/object still gets scanned.
		var str string
		if err := json.Unmarshal(raw, &str); err == nil {
			out[k] = str
		} else {
			out[k] = string(raw)
		}
	}
	return out, nil
}

// --- openvsx / vscode extensions ---------------------------------------------

// vsixLifecycle is the set of npm-style lifecycle script names that run around a
// VS Code / OpenVSX extension's build/publish. "vscode:prepublish" is the hook
// an extension's bundler runs at publish time; the npm install hooks
// (preinstall/install/postinstall) run when an extension's dependencies are
// installed from source. Any of these is a place install-time code can hide.
var vsixLifecycle = []string{
	"vscode:prepublish", "vscode:uninstall",
	"preinstall", "install", "postinstall",
	"prepare", "prepublish", "prepublishOnly", "prepack", "postpack",
}

// extractOpenVSX reads a .vsix (a zip whose contents live under "extension/")
// and surfaces its install/activation manifest for inspection: the npm-style
// lifecycle scripts, the activation events (the triggers that run the
// extension's code), and the declared contribution points. The .vsix is not an
// install-time code runner the way an npm/pip package is — VS Code simply
// unzips it — so the manifest's scripts, activationEvents and contributes are
// the deterministic, bounded signal the gate scans (rather than every bundled
// JS file). A wildcard activationEvent ("*", which activates the extension on
// every editor startup) is flagged by the wildcard-activation rule.
func extractOpenVSX(r io.Reader) ([]Hook, bool, error) {
	manifest, truncated, err := readVsixManifest(r)
	if err != nil {
		return nil, truncated, err
	}
	if manifest == nil {
		return nil, truncated, nil
	}
	scripts, activation, contributes, perr := ParseVSIXManifest(manifest)
	if perr != nil {
		return nil, truncated, nil // a malformed manifest is not our error to raise
	}

	const manifestFile = "extension/package.json"
	var hooks []Hook
	for _, name := range vsixLifecycle {
		cmd, ok := scripts[name]
		if !ok || strings.TrimSpace(cmd) == "" {
			continue
		}
		hooks = append(hooks, Hook{
			Ecosystem: "openvsx",
			Kind:      name,
			Label:     "openvsx:" + name,
			File:      manifestFile,
			Script:    boundScript(cmd),
		})
	}
	if len(activation) > 0 {
		// Render one event per line ("activationEvent: <evt>") so the rules — and
		// the wildcard-activation rule in particular — see each trigger on its own
		// line.
		var b strings.Builder
		for _, e := range activation {
			b.WriteString("activationEvent: ")
			b.WriteString(e)
			b.WriteByte('\n')
		}
		hooks = append(hooks, Hook{
			Ecosystem: "openvsx", Kind: "activation", Label: "openvsx:activation",
			File: manifestFile, Script: boundScript(b.String()),
		})
	}
	if len(contributes) > 0 {
		var b strings.Builder
		for _, c := range contributes {
			b.WriteString("contributes: ")
			b.WriteString(c)
			b.WriteByte('\n')
		}
		hooks = append(hooks, Hook{
			Ecosystem: "openvsx", Kind: "contributes", Label: "openvsx:contributes",
			File: manifestFile, Script: boundScript(b.String()),
		})
	}
	return hooks, truncated, nil
}

// readVsixManifest buffers the .vsix (bounded by maxVsixBytes), opens it as a
// zip, and returns the extension manifest ("extension/package.json", falling
// back to the shallowest package.json). It signals truncation rather than
// erroring when the archive exceeds the buffer bound; a stream that is not a zip
// (or whose central directory was truncated away) returns a nil manifest so the
// caller serves the artifact unscanned (fail-open).
func readVsixManifest(r io.Reader) (manifest []byte, truncated bool, err error) {
	data, err := io.ReadAll(io.LimitReader(r, maxVsixBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxVsixBytes {
		// The archive is larger than we will buffer; the zip central directory at
		// its end was not read, so parsing cannot be relied on. Fail open.
		return nil, true, nil
	}
	zr, zerr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if zerr != nil {
		return nil, false, zerr
	}
	bestDepth := 1 << 30
	for _, f := range zr.File {
		name := path.Clean(strings.TrimPrefix(f.Name, "./"))
		if path.Base(name) != "package.json" {
			continue
		}
		if name == "extension/package.json" {
			return readZipEntry(f)
		}
		if d := strings.Count(name, "/"); d < bestDepth {
			data, _, rerr := readZipEntry(f)
			if rerr == nil {
				bestDepth = d
				manifest = data
			}
		}
	}
	return manifest, false, nil
}

// readZipEntry reads a single zip entry bounded to maxHookFileBytes.
func readZipEntry(f *zip.File) ([]byte, bool, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()
	data, n, rerr := readBounded(rc, maxHookFileBytes)
	if rerr != nil {
		return nil, false, rerr
	}
	return data, n >= maxHookFileBytes, nil
}

// ParseVSIXManifest extracts the "scripts" object, the "activationEvents" list,
// and the top-level contribution-point keys ("contributes") from a VS Code /
// OpenVSX extension package.json. It is a pure, fuzz-friendly parser: it
// tolerates arbitrary surrounding fields and returns empty results (not an
// error) for a manifest missing any of them.
func ParseVSIXManifest(data []byte) (scripts map[string]string, activationEvents []string, contributes []string, err error) {
	var doc struct {
		Scripts          map[string]json.RawMessage `json:"scripts"`
		ActivationEvents []string                   `json:"activationEvents"`
		Contributes      map[string]json.RawMessage `json:"contributes"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, nil, err
	}
	scripts = make(map[string]string, len(doc.Scripts))
	for k, raw := range doc.Scripts {
		var str string
		if uerr := json.Unmarshal(raw, &str); uerr == nil {
			scripts[k] = str
		} else {
			scripts[k] = string(raw)
		}
	}
	for _, e := range doc.ActivationEvents {
		if e = strings.TrimSpace(e); e != "" {
			activationEvents = append(activationEvents, e)
		}
	}
	for k := range doc.Contributes {
		if k = strings.TrimSpace(k); k != "" {
			contributes = append(contributes, k)
		}
	}
	// Stable output so findings/metrics are deterministic across runs.
	sort.Strings(contributes)
	return scripts, activationEvents, contributes, nil
}

// --- python ------------------------------------------------------------------

func extractPython(art Artifact, r io.Reader) ([]Hook, bool, error) {
	// Wheels (.whl) are zip archives that run no install code; only source
	// distributions (sdists: .tar.gz) carry a setup.py / build hook. A wheel
	// filename or media type short-circuits to "no hooks".
	if isWheel(art) {
		return nil, false, nil
	}
	files, truncated, err := readTar(r, true, func(name string) bool {
		base := path.Base(name)
		return base == "setup.py" || base == "pyproject.toml" || base == "setup.cfg"
	})
	if err != nil {
		return nil, truncated, err
	}
	// Keep the shallowest of each kind (the project root copy).
	pick := map[string]collected{}
	depth := map[string]int{"setup.py": 1 << 30, "pyproject.toml": 1 << 30, "setup.cfg": 1 << 30}
	for _, f := range files {
		base := path.Base(f.name)
		if d := strings.Count(f.name, "/"); d < depth[base] {
			depth[base] = d
			pick[base] = f
		}
	}
	var hooks []Hook
	if f, ok := pick["setup.py"]; ok {
		hooks = append(hooks, Hook{
			Ecosystem: "pip", Kind: "setup.py", Label: "python:setup.py",
			File: f.name, Script: boundScript(string(f.data)),
		})
	}
	if f, ok := pick["pyproject.toml"]; ok {
		if backend := ParsePyprojectBuildBackend(f.data); backend != "" && !isStandardPyBuildBackend(backend) {
			hooks = append(hooks, Hook{
				Ecosystem: "pip", Kind: "pyproject-build", Label: "python:pyproject-build",
				File: f.name,
				Script: "build-backend = " + backend + "\n" +
					boundScript(string(f.data)),
			})
		}
	}
	return hooks, truncated, nil
}

func isWheel(art Artifact) bool {
	if strings.HasSuffix(strings.ToLower(art.Filename), ".whl") {
		return true
	}
	if strings.Contains(strings.ToLower(art.MediaType), "wheel") {
		return true
	}
	return false
}

// ParsePyprojectBuildBackend extracts build-system.build-backend from a
// pyproject.toml using a lightweight line scan (no TOML dependency). Pure and
// fuzz-friendly.
func ParsePyprojectBuildBackend(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if k, v, ok := tomlKeyValue(l); ok && k == "build-backend" {
			return v
		}
	}
	return ""
}

// isStandardPyBuildBackend reports whether a build-backend is one of the common,
// trusted backends (so a non-standard custom backend is what we flag).
func isStandardPyBuildBackend(backend string) bool {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "setuptools.build_meta", "setuptools.build_meta:__legacy__",
		"flit_core.buildapi", "poetry.core.masonry.api", "hatchling.build",
		"pdm.backend", "pdm.pep517.api", "maturin", "scikit_build_core.build",
		"mesonpy":
		return true
	default:
		return false
	}
}

// --- cargo -------------------------------------------------------------------

func extractCargo(r io.Reader) ([]Hook, bool, error) {
	// A .crate is a gzip'd tar with entries under "<name>-<version>/".
	files, truncated, err := readTar(r, true, func(name string) bool {
		base := path.Base(name)
		return base == "build.rs" || base == "Cargo.toml"
	})
	if err != nil {
		return nil, truncated, err
	}
	var buildRS *collected
	var cargoToml *collected
	for i := range files {
		f := &files[i]
		base := path.Base(f.name)
		if base == "build.rs" && (buildRS == nil || strings.Count(f.name, "/") < strings.Count(buildRS.name, "/")) {
			buildRS = f
		}
		if base == "Cargo.toml" && (cargoToml == nil || strings.Count(f.name, "/") < strings.Count(cargoToml.name, "/")) {
			cargoToml = f
		}
	}
	var hooks []Hook
	if buildRS != nil {
		hooks = append(hooks, Hook{
			Ecosystem: "cargo", Kind: "build.rs", Label: "cargo:build.rs",
			File: buildRS.name, Script: boundScript(string(buildRS.data)),
		})
	} else if cargoToml != nil && ParseCargoBuildField(cargoToml.data) != "" {
		// A custom build script is declared but lived outside our shallow scan; flag
		// its declaration so the native-build signal is not lost.
		hooks = append(hooks, Hook{
			Ecosystem: "cargo", Kind: "build.rs", Label: "cargo:build.rs",
			File: cargoToml.name, Script: "build = " + ParseCargoBuildField(cargoToml.data),
		})
	}
	return hooks, truncated, nil
}

// ParseCargoBuildField extracts the [package] build = "..." key from a
// Cargo.toml. Pure, lightweight, fuzz-friendly.
func ParseCargoBuildField(data []byte) string {
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") || l == "" {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.ToLower(strings.Trim(l, "[]"))
			continue
		}
		if section != "package" {
			continue
		}
		if k, v, ok := tomlKeyValue(l); ok && k == "build" {
			return v
		}
	}
	return ""
}

// --- rubygems ----------------------------------------------------------------

func extractRubyGems(r io.Reader) ([]Hook, bool, error) {
	// A .gem is an UNCOMPRESSED tar containing metadata.gz (a gzip'd YAML
	// gemspec) and data.tar.gz (the gem's files). Read the outer tar, then the
	// gemspec for extensions + post_install_message, then peek data.tar.gz for the
	// native-extension build scripts.
	outer, truncated, err := readTar(r, false, func(name string) bool {
		base := path.Base(name)
		return base == "metadata.gz" || base == "metadata" || base == "data.tar.gz"
	})
	if err != nil {
		return nil, truncated, err
	}
	var metaRaw, dataRaw []byte
	for _, f := range outer {
		switch path.Base(f.name) {
		case "metadata.gz":
			if g, gerr := gzip.NewReader(bytes.NewReader(f.data)); gerr == nil {
				metaRaw, _, _ = readBounded(g, maxHookFileBytes)
				_ = g.Close()
			}
		case "metadata":
			metaRaw = f.data
		case "data.tar.gz":
			dataRaw = f.data
		}
	}
	if metaRaw == nil {
		return nil, truncated, nil
	}
	extensions, postInstall := ParseGemspecMetadata(metaRaw)

	var hooks []Hook
	if msg := strings.TrimSpace(postInstall); msg != "" {
		hooks = append(hooks, Hook{
			Ecosystem: "rubygems", Kind: "post_install_message", Label: "rubygems:post_install_message",
			File: "metadata", Script: boundScript(msg),
		})
	}
	if len(extensions) > 0 {
		// Pull the extension build scripts (extconf.rb / Rakefile / mkrf_conf.rb)
		// out of data.tar.gz so the rules see their source, not just their names.
		extSources := map[string][]byte{}
		if dataRaw != nil {
			inner, t2, _ := readTar(bytes.NewReader(dataRaw), true, func(name string) bool {
				base := path.Base(name)
				return base == "extconf.rb" || base == "Rakefile" || base == "mkrf_conf.rb" || strings.HasSuffix(base, ".gemspec")
			})
			truncated = truncated || t2
			for _, f := range inner {
				extSources[path.Base(f.name)] = f.data
			}
		}
		for _, ext := range extensions {
			script := "extension: " + ext
			if src, ok := extSources[path.Base(ext)]; ok {
				script = boundScript(string(src))
			}
			hooks = append(hooks, Hook{
				Ecosystem: "rubygems", Kind: "extension", Label: "rubygems:extension",
				File: ext, Script: script,
			})
		}
	}
	return hooks, truncated, nil
}

// ParseGemspecMetadata extracts the `extensions` list and `post_install_message`
// from a serialized Gem::Specification (the YAML in a .gem's metadata.gz). It
// uses a tolerant, dependency-free line scan rather than a full YAML parser, so
// it is pure and fuzz-friendly. Both block scalars and flow/inline forms of the
// message are handled.
func ParseGemspecMetadata(data []byte) (extensions []string, postInstall string) {
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		l := strings.TrimSpace(raw)
		switch {
		case l == "extensions:" || strings.HasPrefix(l, "extensions:"):
			// Inline non-empty value, e.g. "extensions: [ext/foo/extconf.rb]".
			if v := strings.TrimSpace(strings.TrimPrefix(l, "extensions:")); v != "" && v != "[]" {
				extensions = append(extensions, parseInlineList(v)...)
			}
			// Following "- item" block entries.
			for j := i + 1; j < len(lines); j++ {
				e := strings.TrimSpace(lines[j])
				if strings.HasPrefix(e, "- ") {
					extensions = append(extensions, unquoteYAML(strings.TrimSpace(e[2:])))
					continue
				}
				break
			}
		case strings.HasPrefix(l, "post_install_message:"):
			v := strings.TrimSpace(strings.TrimPrefix(l, "post_install_message:"))
			switch {
			case v == "" || v == "|" || v == "|-" || v == ">" || v == ">-":
				// Block scalar: gather subsequent more-indented lines.
				baseIndent := leadingSpaces(raw)
				var b strings.Builder
				for j := i + 1; j < len(lines); j++ {
					if strings.TrimSpace(lines[j]) == "" {
						b.WriteByte('\n')
						continue
					}
					if leadingSpaces(lines[j]) <= baseIndent {
						break
					}
					b.WriteString(strings.TrimSpace(lines[j]))
					b.WriteByte('\n')
				}
				postInstall = b.String()
			default:
				postInstall = unquoteYAML(v)
			}
		}
	}
	return extensions, postInstall
}

// --- shared small helpers ----------------------------------------------------

// tomlKeyValue parses a simple `key = "value"` (or `key = value`) TOML line,
// stripping quotes and a trailing comment. ok is false for a non key/value line.
func tomlKeyValue(line string) (key, value string, ok bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	val := strings.TrimSpace(line[eq+1:])
	// Drop a trailing inline comment outside quotes (best-effort).
	if !strings.HasPrefix(val, "\"") && !strings.HasPrefix(val, "'") {
		if h := strings.IndexByte(val, '#'); h >= 0 {
			val = strings.TrimSpace(val[:h])
		}
	}
	value = strings.Trim(val, "\"'")
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func parseInlineList(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := unquoteYAML(strings.TrimSpace(part)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	return strings.Trim(s, "\"'")
}

func leadingSpaces(s string) int {
	n := 0
	for _, c := range s {
		if c == ' ' {
			n++
			continue
		}
		break
	}
	return n
}

// boundScript caps the scanned text for a single hook so a giant minified blob
// cannot blow up scanning time, while still covering realistic install scripts.
func boundScript(s string) string {
	if len(s) <= maxHookScript {
		return s
	}
	return s[:maxHookScript]
}

var _ = errTruncated // reserved sentinel; truncation is surfaced via the bool path
