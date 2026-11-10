package vulnscan

import (
	"strings"
)

// Artifact identifies the unit handed to the scanning subsystem: a concrete,
// versioned package (or OCI image) flowing through the proxy. Digest is the
// content address the scan Report is cached under.
type Artifact struct {
	// Ecosystem is the normalized ecosystem: npm, pip, cargo, go, nuget, docker.
	Ecosystem string `json:"ecosystem"`
	// Name and Version are the package coordinate.
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// Digest is the content digest (e.g. "sha256:..."), used as the scan-cache key.
	Digest string `json:"digest,omitempty"`
	// Filename is the upstream artifact filename, when known; it disambiguates the
	// embedded-manifest parser (wheel vs sdist, etc.).
	Filename string `json:"filename,omitempty"`
	// MediaType is the artifact content type, when known.
	MediaType string `json:"mediaType,omitempty"`
}

// OSVEcosystem maps a proxy ecosystem name to the OSV.dev ecosystem identifier
// (https://ossf.github.io/osv-schema/#defined-ecosystems). It returns ok=false
// for ecosystems OSV does not cover by package coordinate (e.g. raw docker
// images, which require a layer/OS scanner such as Trivy).
func OSVEcosystem(ecosystem string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return "npm", true
	case "pip", "pypi", "python":
		return "PyPI", true
	case "cargo", "crates", "crates.io":
		return "crates.io", true
	case "go", "golang", "gomod":
		return "Go", true
	case "nuget":
		return "NuGet", true
	case "rubygems", "gem", "gems":
		return "RubyGems", true
	case "composer", "packagist", "php":
		return "Packagist", true
	case "dart", "pub", "flutter":
		return "Pub", true
	case "cran", "r":
		return "CRAN", true
	case "hex", "elixir", "erlang":
		return "Hex", true
	case "cpan", "perl":
		// OSV.dev's "CPAN" ecosystem is keyed by distribution name and version,
		// which a CPAN distribution filename (<Dist>-<Version>.tar.gz) encodes, so a
		// coordinate lookup is possible at the pull layer.
		return "CPAN", true
	case "hackage", "haskell":
		// OSV.dev's "Hackage" ecosystem is keyed by Haskell package name and
		// version, exactly the coordinate a Hackage sdist (<name>-<version>.tar.gz)
		// encodes, so a coordinate lookup is possible at the pull layer.
		return "Hackage", true
	default:
		// Conda, Bazel, Julia, JSR, OpenVSX/VS Code extensions, Nix store paths,
		// Homebrew bottles, Ansible Galaxy collections, and Puppet Forge modules are
		// intentionally absent. OSV.dev defines no Ansible-Galaxy ecosystem (a
		// collection is addressed by a "namespace.name" FQCN that is not an OSV key)
		// nor a Puppet-Forge ecosystem (a module is addressed by an "owner-name" slug
		// that is not an OSV key), so no coordinate lookup is possible at the pull
		// layer for either; both are instead defended by the content / name /
		// provenance / policy gates, with their underlying source repositories covered
		// by the provenance / commit-scanning paths. OSV.dev defines no Homebrew
		// ecosystem (a bottle is addressed by an opaque OCI digest, and a formula
		// coordinate is not an OSV key), so no coordinate lookup is possible at the
		// pull layer; a formula's underlying source is covered via the provenance/
		// commit-scanning paths instead. OSV.dev defines no ecosystem keyed by the conda or
		// Bazel coordinate, nor by the {namespace}.{extension} coordinate an IDE
		// extension is addressed by (OpenVSX / the VS Code Marketplace are not an OSV
		// ecosystem), nor by a Nix store hash / NAR SHA-256 (a binary cache addresses
		// content by hash, never a name/semver). OSV.dev does define a "Julia"
		// ecosystem, but it is keyed by human package name and version, whereas the
		// Julia Pkg Server Protocol this proxy fronts addresses packages only by UUID
		// and git-tree-sha1 — never a name/semver — so no coordinate OSV lookup is
		// possible at the pull layer. JSR is also absent: OSV.dev defines no "JSR"
		// ecosystem, and although JSR is npm-adjacent (its packages are mirrored to
		// npm under the synthetic "@jsr/<scope>__<name>" name served from npm.jsr.io),
		// a JSR-native coordinate ("@scope/name") is not an npm name and OSV publishes
		// no JSR-keyed advisories, so mapping it to "npm" would produce false lookups.
		// These artifacts' underlying sources are covered
		// elsewhere: conda packages under PyPI/CRAN/etc., and a Bazel module, Julia
		// package, or Nix derivation under its source repository (commonly GitHub),
		// which the provenance/commit-scanning paths cover. Extensions are instead
		// defended by the install/activation content gate (internal/installhooks)
		// plus the name/provenance/policy gates.
		return "", false
	}
}

// purlType maps a proxy ecosystem to the Package-URL type component
// (https://github.com/package-url/purl-spec).
func purlType(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return "npm"
	case "pip", "pypi", "python":
		return "pypi"
	case "cargo", "crates", "crates.io":
		return "cargo"
	case "go", "golang", "gomod":
		return "golang"
	case "nuget":
		return "nuget"
	case "rubygems", "gem", "gems":
		return "gem"
	case "composer", "packagist", "php":
		return "composer"
	case "docker", "oci":
		return "oci"
	case "conan":
		return "conan"
	case "swift":
		return "swift"
	case "dart", "pub", "flutter":
		return "pub"
	case "conda":
		return "conda"
	case "cran", "r":
		return "cran"
	case "hex", "elixir", "erlang":
		return "hex"
	case "cpan", "perl":
		return "cpan"
	case "hackage", "haskell":
		// "hackage" is an official Package-URL type for Haskell packages.
		return "hackage"
	case "jsr":
		// No official purl type exists for JSR; "jsr" is used as the descriptive
		// type so the "@scope/name" coordinate still renders a stable purl.
		return "jsr"
	case "bazel":
		// No official purl type exists for Bazel modules; "bazel" is used as the
		// descriptive type so the coordinate still renders a stable purl.
		return "bazel"
	case "julia":
		// No official purl type exists for Julia; "julia" is used as the descriptive
		// type so the UUID/git-tree-sha1 coordinate still renders a stable purl.
		return "julia"
	case "nix":
		// No official purl type exists for Nix store paths; "nix" is used as the
		// descriptive type so the store-hash / NAR SHA-256 coordinate still renders a
		// stable purl.
		return "nix"
	case "homebrew", "brew":
		// No official purl type exists for Homebrew bottles; "homebrew" is used as
		// the descriptive type so the formula name/version coordinate still renders a
		// stable purl.
		return "homebrew"
	case "ansible", "galaxy":
		// No official purl type exists for Ansible collections; "ansible" is used as
		// the descriptive type so the "namespace.name" coordinate still renders a
		// stable purl.
		return "ansible"
	case "puppet", "forge":
		// No official purl type exists for Puppet modules; "puppet" is used as the
		// descriptive type so the "owner-name" coordinate still renders a stable purl.
		return "puppet"
	default:
		return strings.ToLower(strings.TrimSpace(ecosystem))
	}
}

// PackageURL renders a Package-URL (purl) for a component. The namespace is split
// out of names that carry one (npm scopes, Go module paths) per the purl spec.
func PackageURL(ecosystem, name, version string) string {
	typ := purlType(ecosystem)
	namespace, base := splitNamespace(typ, name)

	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteByte('/')
	if namespace != "" {
		b.WriteString(purlEscapePath(namespace))
		b.WriteByte('/')
	}
	b.WriteString(purlEscape(base))
	if version != "" {
		b.WriteByte('@')
		b.WriteString(purlEscape(version))
	}
	return b.String()
}

// splitNamespace separates a purl namespace from the base name for ecosystems
// whose names embed one.
func splitNamespace(typ, name string) (namespace, base string) {
	name = strings.TrimSpace(name)
	switch typ {
	case "npm", "jsr":
		// Scoped packages: "@scope/name".
		if strings.HasPrefix(name, "@") {
			if i := strings.Index(name, "/"); i > 0 {
				return name[:i], name[i+1:]
			}
		}
		return "", name
	case "golang":
		// Go module paths: everything up to the last segment is the namespace.
		if i := strings.LastIndex(name, "/"); i > 0 {
			return name[:i], name[i+1:]
		}
		return "", name
	case "composer":
		// Composer names are "vendor/package": the vendor is the namespace.
		if i := strings.Index(name, "/"); i > 0 {
			return name[:i], name[i+1:]
		}
		return "", name
	default:
		return "", name
	}
}

// purlEscape percent-encodes a single purl segment per the Package-URL spec:
// every character that is not "unreserved" (RFC 3986 — ALPHA / DIGIT / "-" / "."
// / "_" / "~") is percent-encoded. Notably this encodes '@' (to "%40"), which
// url.PathEscape leaves intact, so scoped npm names render canonically.
func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isPurlUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex(c >> 4))
		b.WriteByte(upperHex(c & 0x0f))
	}
	return b.String()
}

// purlEscapePath percent-encodes a namespace, preserving '/' separators.
func purlEscapePath(s string) string {
	parts := strings.Split(s, "/")
	for i, p := range parts {
		parts[i] = purlEscape(p)
	}
	return strings.Join(parts, "/")
}

func isPurlUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	default:
		return false
	}
}

func upperHex(nibble byte) byte {
	if nibble < 10 {
		return '0' + nibble
	}
	return 'A' + (nibble - 10)
}
