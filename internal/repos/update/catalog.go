package update

import "sort"

// The formats the maintenance updater writes, and how. Every lock-file format
// internal/lockfiles parses has an entry (catalog_test.go): a new parser cannot
// be left out without someone deciding how its lock files are updated — or
// saying why they are not. docs/repositories.md#maintenance-updates is
// generated from this table (Formats, ReferenceTable).

// listedOnly is why a format's ecosystem is not updated at all.
const listedOnly = "The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet."

var catalog = map[string]FormatSupport{
	"npm/package-lock.json": {
		Method: Native, Fallback: Sandbox, Tool: "npm", Manifests: []string{"package.json"},
		Reason: "Native when the new version declares the same dependencies, platform and installation metadata as the old one (its packument entries compare equal): `version`, `resolved` and `integrity` of every install position of the old version are rewritten from the bytes the proxy verified. Otherwise `npm update --package-lock-only` re-resolves the tree in the sandbox, its packument trimmed to the vetted version.",
	},
	"npm/npm-shrinkwrap.json": {
		Method: Native, Fallback: Sandbox, Tool: "npm", Manifests: []string{"package.json"},
		Reason: "As `package-lock.json`, of which it is the published form.",
	},
	"npm/yarn.lock": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "A yarn.lock entry records the resolution of each range, keyed by the ranges; moving one entry means re-resolving with Yarn itself, which the sandbox does not run yet.",
	},
	"npm/pnpm-lock.yaml": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "pnpm keys snapshots and their dependency graph by version and peer suffix; a rewrite needs pnpm itself, which the sandbox does not run yet.",
	},
	"pip/requirements.txt": {
		Method: Native, Fallback: Unsupported, Manifests: []string{"requirements.in", "pyproject.toml"},
		Reason: "Native when the new release declares the same requirements (Requires-Dist, from the index's JSON API) and every other pinned project's requirements allow it: the `==` pin and its `--hash` lines (one per distribution file of the release, from the bytes the proxy verified) are rewritten. A release with other requirements is not proposed: re-resolving needs the file's pip-tools or uv input, which the sandbox does not run yet.",
	},
	"pip/Pipfile.lock": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "Pipfile.lock carries a hash of the Pipfile and is re-resolved by Pipenv, which the sandbox does not run yet.",
	},
	"pip/poetry.lock": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "poetry.lock carries a content hash of pyproject.toml and is re-resolved by Poetry, which the sandbox does not run yet.",
	},
	"pip/uv.lock": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "uv.lock records every release's dependency markers per resolution fork; it is re-resolved by uv, which the sandbox does not run yet.",
	},
	"pip/pdm.lock": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "pdm.lock carries a content hash of pyproject.toml and is re-resolved by PDM, which the sandbox does not run yet.",
	},
	"cargo/Cargo.lock": {
		Method: Native, Fallback: Sandbox, Tool: "cargo", Manifests: []string{"Cargo.toml"},
		Reason: "Native when the new version's index entry declares the same dependencies, features and links: `version` and `checksum` (the SHA-256 of the .crate the proxy verified) are rewritten, and references that name the old version. Otherwise `cargo update --precise` re-resolves in the sandbox (crates.io dependencies).",
	},
	"go/go.mod": {
		Method: Native, Fallback: Sandbox, Tool: "go", Manifests: []string{"go.mod"},
		Reason: "Native when the new version's go.mod requires the same modules at the same versions: the `require` line in go.mod and the `h1:` lines in go.sum (the module hash of the zip and of the go.mod the proxy verified) are rewritten. Otherwise `go get` re-resolves in the sandbox (minimal version selection within the major version).",
	},
	"go/go.sum": {
		Method: Native, Fallback: Sandbox, Tool: "go", Manifests: []string{"go.mod"},
		Reason: "Written together with go.mod (see go.mod).",
	},
	"nuget/packages.lock.json": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "`contentHash` is the SHA-512 of the package with its signature removed, which the proxy cannot recompute from the bytes it serves; the lock is re-resolved by `dotnet restore`, which the sandbox does not run yet. " + listedOnly,
	},
	"maven/gradle.lockfile": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "Gradle writes the lock from the build's own resolution, which only running the build reproduces. " + listedOnly,
	},
	"maven/pom.xml": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "A POM is the build itself, not a lock file; changing its versions is a change of the build. " + listedOnly,
	},
	"rubygems/Gemfile.lock": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "Bundler re-resolves the whole lock (`bundle lock --update`), which the sandbox does not run yet. " + listedOnly,
	},
	"composer/composer.lock": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "composer.lock carries a content hash of composer.json and dist references only Composer computes. " + listedOnly,
	},
	"docker/Dockerfile": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "Base images are pinned by digest of a tag, not by a version within a range; moving them is not a dependency update the updater can vet against a declared constraint.",
	},
	"docker/compose": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "As Dockerfile.",
	},
	"git/.gitmodules": {
		Method: Unsupported, Fallback: Unsupported,
		Reason: "Submodules are pinned to commits, which have no versions to order and no package content the LLM scan vets as a package.",
	},
}

// unsupportedEcosystems are the formats of ecosystems whose versions are not
// listed, with a word on what else stands in the way.
var unsupportedEcosystems = map[string]string{
	"conda/conda-lock.yml":          "conda-lock re-solves the whole environment per platform.",
	"conda/@EXPLICIT spec":          "An explicit spec is the output of a solve of the whole environment.",
	"conda/pixi.lock":               "pixi re-solves every environment and platform together.",
	"cran/renv.lock":                "renv records no digests to rewrite, and renv itself snapshots the library.",
	"hex/mix.lock":                  "Mix evaluates mix.lock, and its outer and inner checksums are computed by Hex.",
	"swift/Package.resolved":        "SwiftPM pins registry releases without a checksum and source-control pins by revision.",
	"dart/pubspec.lock":             "pub re-resolves the whole lock (`dart pub upgrade`).",
	"julia/Manifest.toml":           "Pkg records git-tree hashes of the source trees, which Pkg computes.",
	"bazel/MODULE.bazel.lock":       "Bzlmod records registry file hashes of every visited version, which Bazel computes.",
	"nix/flake.lock":                "Flake inputs are source revisions with NAR hashes, not registry versions.",
	"terraform/.terraform.lock.hcl": "Provider hashes cover every platform's zip (`zh:`/`h1:`), which `terraform providers lock` computes.",
	"terraform/*.tf modules":        "Module versions are written in configuration, not a lock file.",
	"terraform/*.tf overrides":      "Module versions are written in configuration, not a lock file.",
	"conan/conan.lock":              "Conan locks recipe revisions computed by Conan.",
	"cpan/cpanfile.snapshot":        "Carton re-resolves the snapshot.",
	"hackage/cabal.project.freeze":  "cabal re-solves the plan.",
	"hackage/stack.yaml.lock":       "Stack records snapshot and package hashes it computes.",
	"jsr/deno.lock":                 "Deno locks module file sets by their own integrity hashes.",
	"helm/Chart.lock":               "Chart.lock's digest is a hash of the dependency list Helm computes.",
	"helm/requirements.lock":        "As Chart.lock.",
	"homebrew/Brewfile.lock.json":   "Homebrew no longer writes Brewfile.lock.json.",
	"ansible/requirements.yml":      "A requirements file pins versions without digests and is not resolved by a lock.",
	"puppet/Puppetfile":             "r10k evaluates the Puppetfile; it records no digests.",
}

func init() {
	for k, why := range unsupportedEcosystems {
		catalog[k] = FormatSupport{Method: Unsupported, Fallback: Unsupported, Reason: why + " " + listedOnly}
	}
	for k, f := range catalog {
		t, format := splitKey(k)
		f.Type, f.Format = t, format
		catalog[k] = f
	}
}

func splitKey(k string) (string, string) {
	for i := 0; i < len(k); i++ {
		if k[i] == '/' {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}

// Format returns how a "<type>/<format>" lock file is updated.
func Format(key string) (FormatSupport, bool) {
	f, ok := catalog[key]
	if ok {
		f.Manifests = append([]string(nil), f.Manifests...)
	}
	return f, ok
}

// Formats returns every format's support, sorted by type and format.
func Formats() []FormatSupport {
	out := make([]FormatSupport, 0, len(catalog))
	for k := range catalog {
		f, _ := Format(k)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Format < out[j].Format
	})
	return out
}
