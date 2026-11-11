package hex

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// A Hex repository (the Elixir/Erlang package registry, hex.pm, served from
// repo.hex.pm) is a small static HTTP tree of signed registry resources and the
// immutable release tarballs they describe. The proxy mounts a repository at its
// route root ("<publicBase>/v1/<name>") and honors the registry-v2 layout:
//
//	/names                              all package names (signed protobuf, mutable)
//	/versions                           all packages' versions (signed protobuf, mutable)
//	/packages/<name>                    one package's releases (signed protobuf, mutable)
//	/tarballs/<name>-<version>.tar      a release tarball (immutable, verified)
//	/installs/...                       Hex/Rebar self-install tree (live pass-through)
//
// The three registry resources are gzip-compressed, protobuf-encoded, and wrapped
// in a Signed envelope; they change whenever a package publishes, so they are
// revalidated live rather than cached. A tarball filename pins its
// name-and-version coordinate, so a tarball is immutable and content-addressable;
// on a cache miss the backend fetches the sibling /packages/<name> resource,
// reads the release's outer_checksum (a SHA-256 over the whole tarball), and
// verifies the fetched bytes against it before they are cached or served (see
// registry.go / checksum.go).
//
// The /installs/ tree is not package content: it is how Mix and Hex install and
// update the Hex and Rebar3 tools themselves. With HEX_MIRROR pointing at the
// proxy (and HEX_BUILDS_URL unset) the real clients fetch it from the mirror:
//
//	/installs/hex-1.x.csv[.signed]                  Hex builds list + its RSA signature
//	/installs/<elixir>/hex-<version>.ez             a Hex build (Mix archive)
//	/installs/rebar3-1.x.csv[.signed]               Rebar3 builds list + signature
//	/installs/<elixir>/rebar3-<version>             a Rebar3 build (escript)
//
// Hex itself reads hex-1.x.csv on (at most daily) `mix deps.get` runs to announce
// a newer Hex — a 501 there is the "Failed to check for new Hex version" warning
// — and `mix local.hex` / `mix local.rebar` read a list, check its .signed
// sibling against the public key built into Mix (through Elixir 1.18; 1.19+
// relies on HTTPS alone), and then download the build whose SHA-512 the list
// records. Elixir 1.18+ uses the names hex.csv / rebar.csv and
// "-otp-<release>"-suffixed builds; both generations are recognized (see
// classifyInstall). The whole tree is served live and byte-exact — see
// kindInstall for why the builds are deliberately not cached.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a Hex repository path can
// address.
type resourceKind int

const (
	// kindNames is the /names registry resource (all package names). Mutable,
	// served live.
	kindNames resourceKind = iota
	// kindVersions is the /versions registry resource (every package's released
	// versions). Mutable, served live.
	kindVersions
	// kindPackageIndex is the /packages/<name> registry resource (one package's
	// releases, each carrying an outer_checksum). Mutable, served live; also the
	// digest source the backend verifies tarballs against.
	kindPackageIndex
	// kindTarball is a release tarball /tarballs/<name>-<version>.tar, pinned by
	// name and version. Immutable, cacheable, verified against the sibling
	// /packages/<name> resource's outer_checksum.
	kindTarball
	// kindInstall is a file of the /installs/ tree: a Hex or Rebar builds list
	// (CSV), its detached signature, or one of the builds the list describes.
	// Everything in the tree is served live and byte-exact, and nothing in it is
	// cached or given a package coordinate:
	//
	//   - The lists are mutable (rows are added per release) and RSA-signed; Mix
	//     through Elixir 1.18 verifies the signature over the exact bytes.
	//   - A build is versioned by name but not content-addressed. Its only
	//     integrity record is its SHA-512 row in the mutable list, which the
	//     client checks on every install. A copy cached here could only ever go
	//     stale against that list — a rebuilt archive would then fail every
	//     client's checksum check until an operator purged the entry — while the
	//     client's own check already rejects anything the list does not vouch
	//     for, so caching adds no integrity and serving live costs one ~1 MB
	//     transfer per tool upgrade.
	//   - Caching here means the gated pipeline, which needs a Name+Version
	//     coordinate in the Hex package namespace. The Hex and Rebar tools are
	//     not hex.pm packages (there is no /packages/hex), so a coordinate would
	//     be invented and the registry-backed gates would evaluate a package
	//     that does not exist.
	kindInstall
)

// tarballExt is the single extension a Hex release tarball carries. The outer
// archive is an uncompressed tar (its contents.tar.gz member is compressed
// inside it).
const tarballExt = ".tar"

// resource is the parsed classification of an inbound Hex repository request.
type resource struct {
	kind resourceKind
	// filename is the final path component (a registry-resource name or the
	// tarball file); for kindInstall it is the path below /installs/.
	filename string
	// name/version form the package coordinate. name is set for kindPackageIndex
	// and kindTarball; version only for kindTarball.
	name    string
	version string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the Hex repository layout, so an unrecognized request is
// reported as unsupported rather than blindly proxied. Every path segment is
// checked for emptiness and path traversal because the upstream URL is built
// from these segments.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	switch segs[0] {
	case "names":
		if len(segs) == 1 {
			return resource{kind: kindNames, filename: "names"}, true
		}
	case "versions":
		if len(segs) == 1 {
			return resource{kind: kindVersions, filename: "versions"}, true
		}
	case "packages":
		// /packages/<name> — exactly one trailing segment, the package name.
		if len(segs) == 2 && validPackageName(segs[1]) {
			return resource{kind: kindPackageIndex, filename: segs[1], name: segs[1]}, true
		}
	case "tarballs":
		// /tarballs/<name>-<version>.tar — exactly one trailing segment.
		if len(segs) == 2 {
			if name, version, ok := parseTarballFilename(segs[1]); ok {
				return resource{kind: kindTarball, filename: segs[1], name: name, version: version}, true
			}
		}
	case "installs":
		// /installs/<list> or /installs/<elixir>/<build> — a fixed allowlist.
		if file, ok := classifyInstall(segs[1:]); ok {
			return resource{kind: kindInstall, filename: file}, true
		}
	}
	return resource{}, false
}

// installTools are the tools distributed through the /installs/ tree. "rebar"
// names both the retired Rebar 2 list (rebar-1.x.csv) and the list Elixir 1.18+
// reads for Rebar3 (rebar.csv).
var installTools = map[string]bool{"hex": true, "rebar": true, "rebar3": true}

// maxInstallVersionLen bounds a version segment in the /installs/ tree; real
// ones ("1.15.0-rc.0", "2.7.0-otp-27") are a fraction of this.
const maxInstallVersionLen = 64

// classifyInstall validates the path segments below "/installs/" against the
// exact shapes the real clients request and returns the path relative to
// /installs/. Nothing else in the tree is proxied:
//
//	<tool>-<N>.x.csv[.signed] | <tool>.csv[.signed]     builds list and signature
//	<elixir>/hex-<version>[-otp-<release>].ez           Hex build
//	<elixir>/rebar3-<version>[-otp-<release>]           Rebar3 build
//	<elixir>/rebar-<version>                            Rebar 2 build (retired)
func classifyInstall(segs []string) (string, bool) {
	switch len(segs) {
	case 1:
		if isInstallList(segs[0]) {
			return segs[0], true
		}
	case 2:
		if isInstallVersion(segs[0]) && isInstallBuild(segs[1]) {
			return segs[0] + "/" + segs[1], true
		}
	}
	return "", false
}

// isInstallList reports whether name is a builds list or its detached
// signature: "<tool>.csv" (Elixir 1.18+) or "<tool>-<N>.x.csv" (earlier
// releases; the series has only ever been "1.x"), optionally with ".signed".
func isInstallList(name string) bool {
	stem, ok := strings.CutSuffix(strings.TrimSuffix(name, ".signed"), ".csv")
	if !ok {
		return false
	}
	tool, series, hasSeries := strings.Cut(stem, "-")
	if !installTools[tool] {
		return false
	}
	if !hasSeries {
		return true
	}
	major, ok := strings.CutSuffix(series, ".x")
	return ok && isDigits(major)
}

// isInstallBuild reports whether name is a build artifact: a Hex archive
// "hex-<version>.ez" or an extension-less Rebar escript "rebar3-<version>" /
// "rebar-<version>", where <version> may carry the "-otp-<release>" qualifier.
func isInstallBuild(name string) bool {
	tool, version, ok := strings.Cut(name, "-")
	if !ok || !installTools[tool] {
		return false
	}
	if tool == "hex" {
		if version, ok = strings.CutSuffix(version, ".ez"); !ok {
			return false
		}
	}
	return isInstallVersion(version)
}

// isInstallVersion reports whether s looks like a version as the /installs/
// tree spells them: an Elixir release directory ("1.16.0", "1.15.0-rc.0") or a
// build version with its optional OTP qualifier ("2.7.0", "3.22.0-otp-27"). It
// must start with a digit and consist of [0-9A-Za-z.+-] only, so the segment is
// inert in the upstream URL (no separators, no escapes, never "." or "..").
func isInstallVersion(s string) bool {
	if s == "" || len(s) > maxInstallVersionLen || s[0] < '0' || s[0] > '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '.' || c == '-' || c == '+':
		default:
			return false
		}
	}
	return true
}

// isDigits reports whether s is a non-empty run of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validPackageName reports whether s is a plausible Hex package name. Hex
// restricts names to lowercase ASCII letters, digits, and underscores; applying
// the rule here keeps the /packages/<name> route from proxying arbitrary paths
// and guarantees the coordinate fed to the gates is well-formed.
func validPackageName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_':
		default:
			return false
		}
	}
	return true
}

// parseTarballFilename decodes a Hex tarball filename into its coordinate. A
// tarball is "<name>-<version>.tar". Hex package names may not contain a hyphen,
// so the name is everything before the first hyphen and the version is
// everything between it and the ".tar" extension (which preserves pre-release
// versions such as "1.0.0-rc.1"). The name is validated against Hex's naming
// rule; the version is only checked for non-emptiness and traversal safety.
func parseTarballFilename(name string) (pkg, version string, ok bool) {
	if !strings.HasSuffix(name, tarballExt) {
		return "", "", false
	}
	base := name[:len(name)-len(tarballExt)]
	i := strings.IndexByte(base, '-')
	if i <= 0 || i >= len(base)-1 {
		return "", "", false
	}
	pkg = base[:i]
	version = base[i+1:]
	if !validPackageName(pkg) || version == "" {
		return "", "", false
	}
	// The version is part of the upstream path; reject any residual traversal
	// metacharacters so it cannot escape the tarballs/ directory.
	if strings.ContainsAny(version, "/\\") || version == "." || version == ".." {
		return "", "", false
	}
	return pkg, version, true
}

// cacheable reports whether the resource may be cached. Only tarballs are
// immutable (their filename pins the version); the three registry resources are
// mutable and revalidated live, and the /installs/ tree is served live as a
// whole (see kindInstall).
func (r resource) cacheable() bool {
	return r.kind == kindTarball
}

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). A release tarball is what Mix unpacks and compiles;
// the three signed registry resources are indexes a client only reads.
//
// The /installs/ tree holds both classes. A builds list and its detached
// signature are documents; a build is a Mix archive or an escript the client
// installs and then runs, so it is a payload even though it is served live and
// never cached (cacheable() is false for it). Only a name that is positively a
// list — a single segment directly below /installs/ that isInstallList accepts
// — is called metadata: everything else the tree serves is a build.
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindTarball:
		return backends.Payload()
	case kindNames, kindVersions, kindPackageIndex:
		return backends.Metadata()
	case kindInstall:
		if !strings.Contains(r.filename, "/") && isInstallList(r.filename) {
			return backends.Metadata()
		}
		// A Hex or rebar3 build: an escript or a Mix archive, one file the client
		// installs and runs.
		return backends.PayloadFile()
	default:
		return backends.Artifact{}
	}
}

// verifiableFile reports whether the resource is a tarball the backend should
// verify against the sibling /packages/<name> resource.
func (r resource) verifiableFile() bool {
	return r.kind == kindTarball
}

// coordinateName returns the package name used to address the artifact in the
// admission gates. Empty for the /names and /versions resources and for the
// /installs/ tree, none of which is a hex.pm package.
func (r resource) coordinateName() string {
	return r.name
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindNames:
		return "names"
	case kindVersions:
		return "versions"
	case kindPackageIndex:
		return "package-index"
	case kindTarball:
		return "tarball"
	case kindInstall:
		return "install"
	default:
		return "other"
	}
}

// isRegistryResource reports whether the resource is one of the signed protobuf
// registry documents (names/versions/packages), as opposed to a tarball.
func (r resource) isRegistryResource() bool {
	return r.kind == kindNames || r.kind == kindVersions || r.kind == kindPackageIndex
}
