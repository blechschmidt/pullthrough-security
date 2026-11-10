package vulnscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
)

// maxArtifactBytes bounds how many bytes of an artifact the extractor buffers to
// parse embedded manifests. The primary component is always produced from the
// coordinate regardless of size; only the (best-effort) embedded-dependency
// extraction is skipped for artifacts larger than this, so a pathological upload
// cannot exhaust memory.
const maxArtifactBytes = 64 << 20 // 64 MiB

// maxManifestBytes bounds an individual embedded manifest (package.json, go.mod,
// .nuspec) read out of an archive.
const maxManifestBytes = 4 << 20 // 4 MiB

// Extract builds a CycloneDX SBOM for an artifact. The artifact's own coordinate
// always becomes the SBOM's primary component; when content is supplied and an
// embedded manifest can be parsed (npm package.json, Go go.mod, ...), declared
// dependencies are added as components. Extraction is best-effort: a malformed or
// unrecognized archive yields a primary-component-only SBOM and a nil error, so a
// scan is never blocked by an unparseable artifact.
//
// content may be nil (metadata-only SBOM). The caller owns content and must close
// it; Extract only reads.
func Extract(art Artifact, content io.Reader) (*SBOM, error) {
	sbom := newSBOM()
	primary := primaryComponent(art)
	sbom.Metadata.Component = &primary

	if content != nil {
		data, err := readCapped(content, maxArtifactBytes)
		if err != nil {
			// A read error still yields a valid primary-only SBOM; surface nothing
			// fatal so scanning proceeds on the coordinate alone.
			sbom.Properties = appendProp(sbom.Properties, "pullthrough:extract:warning", "artifact read truncated: "+err.Error())
		}
		if len(data) > 0 && len(data) < maxArtifactBytes {
			extractEmbedded(sbom, art, data)
		} else if len(data) >= maxArtifactBytes {
			sbom.Properties = appendProp(sbom.Properties, "pullthrough:extract:skipped", "artifact exceeds embedded-manifest parse limit")
		}
	}

	sbom.finalize()
	return sbom, nil
}

// primaryComponent builds the SBOM's primary component from the artifact
// coordinate.
func primaryComponent(art Artifact) Component {
	typ := "library"
	if strings.EqualFold(art.Ecosystem, "docker") || strings.EqualFold(art.Ecosystem, "oci") {
		typ = "container"
	}
	group, name := splitNamespace(purlType(art.Ecosystem), art.Name)
	c := Component{
		Type:      typ,
		Group:     group,
		Name:      name,
		Version:   art.Version,
		PURL:      PackageURL(art.Ecosystem, art.Name, art.Version),
		Scope:     "required",
		ecosystem: strings.ToLower(strings.TrimSpace(art.Ecosystem)),
	}
	if art.Digest != "" {
		c.Properties = appendProp(c.Properties, "pullthrough:digest", art.Digest)
	}
	c.BOMRef = bomRef(c)
	return c
}

// extractEmbedded dispatches embedded-manifest parsing by ecosystem. Failures are
// swallowed (best-effort): the SBOM is still valid with just the primary
// component.
func extractEmbedded(sbom *SBOM, art Artifact, data []byte) {
	switch strings.ToLower(strings.TrimSpace(art.Ecosystem)) {
	case "npm":
		extractNPM(sbom, data)
	case "go", "golang", "gomod":
		extractGo(sbom, art, data)
	case "nuget":
		extractNuGet(sbom, data)
	case "pip", "pypi", "python":
		extractPyPI(sbom, data)
	}
}

// extractNPM reads "package/package.json" from an npm tarball (gzip+tar) and adds
// its declared dependencies as components. npm dependency specifiers are version
// ranges, not pins, so they are recorded for transparency with the constraint in
// a property but left without a concrete version (and therefore not queried for
// vulnerabilities, which would otherwise produce imprecise matches).
func extractNPM(sbom *SBOM, data []byte) {
	pj, ok := readTarGzFile(data, func(name string) bool {
		return name == "package/package.json" || strings.HasSuffix(name, "/package.json") && strings.Count(name, "/") == 1
	})
	if !ok {
		return
	}
	var manifest struct {
		Dependencies         map[string]string `json:"dependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		License              json.RawMessage   `json:"license"`
		Licenses             json.RawMessage   `json:"licenses"`
	}
	if err := json.Unmarshal(pj, &manifest); err != nil {
		return
	}
	// The tarball's package.json describes the artifact itself, so its license is
	// the primary component's declared license.
	if expr := npmLicenseExpression(manifest.License, manifest.Licenses); expr != "" &&
		sbom.Metadata != nil && sbom.Metadata.Component != nil {
		setLicenseExpression(sbom.Metadata.Component, expr)
	}
	add := func(deps map[string]string, scope string) {
		for name, constraint := range deps {
			group, base := splitNamespace("npm", name)
			c := Component{
				Type:  "library",
				Group: group,
				Name:  base,
				PURL:  PackageURL("npm", name, ""),
				Scope: scope,
			}
			if constraint != "" {
				c.Properties = appendProp(c.Properties, "pullthrough:versionConstraint", constraint)
			}
			sbom.addComponent(c)
		}
	}
	add(manifest.Dependencies, "required")
	add(manifest.OptionalDependencies, "optional")
	add(manifest.PeerDependencies, "optional")
}

// extractGo reads "<module>@<version>/go.mod" from a Go module zip and adds its
// require directives as components. Go require versions are concrete (semantic
// versions or pseudo-versions), so these components are scannable for
// vulnerabilities.
func extractGo(sbom *SBOM, art Artifact, data []byte) {
	gomod, ok := readZipFile(data, func(name string) bool {
		return strings.HasSuffix(name, "/go.mod") || name == "go.mod"
	})
	if !ok {
		return
	}
	for _, req := range parseGoRequires(gomod) {
		group, base := splitNamespace("golang", req.path)
		sbom.addComponent(Component{
			Type:      "library",
			Group:     group,
			Name:      base,
			Version:   req.version,
			PURL:      PackageURL("go", req.path, req.version),
			Scope:     "required",
			ecosystem: "go",
		})
	}
}

// extractNuGet reads the .nuspec from a NuGet package (a zip) and records its
// declared dependencies. NuGet dependency versions are ranges, recorded for
// transparency but not queried.
func extractNuGet(sbom *SBOM, data []byte) {
	nuspec, ok := readZipFile(data, func(name string) bool {
		return strings.HasSuffix(strings.ToLower(name), ".nuspec") && !strings.Contains(name, "/")
	})
	if !ok {
		return
	}
	if expr := parseNuspecLicense(nuspec); expr != "" &&
		sbom.Metadata != nil && sbom.Metadata.Component != nil {
		setLicenseExpression(sbom.Metadata.Component, expr)
	}
	for _, dep := range parseNuspecDependencies(nuspec) {
		c := Component{
			Type:  "library",
			Name:  dep.id,
			PURL:  PackageURL("nuget", dep.id, ""),
			Scope: "required",
		}
		if dep.version != "" {
			c.Properties = appendProp(c.Properties, "pullthrough:versionConstraint", dep.version)
		}
		sbom.addComponent(c)
	}
}

// --- archive helpers --------------------------------------------------------

// readTarGzFile scans a gzip-compressed tar archive for the first entry whose
// name satisfies match and returns its (capped) contents.
func readTarGzFile(data []byte, match func(name string) bool) ([]byte, bool) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, false
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if match(strings.TrimPrefix(hdr.Name, "./")) {
			b, err := readCapped(tr, maxManifestBytes)
			if err != nil {
				return nil, false
			}
			return b, true
		}
	}
}

// readZipFile scans a zip archive for the first entry whose name satisfies match
// and returns its (capped) contents.
func readZipFile(data []byte, match func(name string) bool) ([]byte, bool) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false
	}
	for _, f := range zr.File {
		if !match(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, false
		}
		b, err := readCapped(rc, maxManifestBytes)
		rc.Close()
		if err != nil {
			return nil, false
		}
		return b, true
	}
	return nil, false
}

// readCapped reads up to max bytes from r. It returns io.ErrShortBuffer (along
// with the first max bytes) when the source exceeds the cap, so callers can
// decide whether truncation is acceptable.
func readCapped(r io.Reader, max int) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return buf, err
	}
	if len(buf) > max {
		return buf[:max], io.ErrShortBuffer
	}
	return buf, nil
}

// appendProp appends a CycloneDX property.
func appendProp(props []NameValue, name, value string) []NameValue {
	return append(props, NameValue{Name: name, Value: value})
}
