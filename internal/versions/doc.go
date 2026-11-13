// Package versions is how each package ecosystem spells, orders and constrains
// versions. The repository updater uses it to order the versions a registry
// lists, to keep only those a manifest's declared constraint allows (npm and
// Cargo semver ranges, PEP 440 specifiers, Maven and NuGet ranges, RubyGems
// requirements), and to classify a bump as patch, minor or major when it has
// to fall back to a default policy.
//
// Each Scheme follows the tool that decides the question for real, because a
// wrong "allows" proposes an upgrade the ecosystem would call incompatible:
//
//   - npm: node-semver v7 as npm uses it (Range, satisfies, strict mode),
//     with a leading "v" or "=" tolerated on a version the way semver.clean
//     does. package.json specs that are no range (git, file, link, URL,
//     workspace, tarball, dist-tag) are ErrNoConstraint.
//   - cargo: the semver crate (1.0) Cargo resolves with: Version and
//     VersionReq, including its pre-release matching rule.
//   - pip: PEP 440 as the packaging library implements it (Version,
//     Specifier, SpecifierSet.contains with pre-releases left unspecified).
//   - go: golang.org/x/mod/semver. Go has no ranges; SameMajor is the set of
//     versions minimal version selection may move to within one module path.
//   - nuget: NuGet.Versioning (NuGetVersion, VersionRange, FloatRange).
//   - maven: maven-artifact's ComparableVersion and VersionRange (Maven 3.9).
//   - rubygems: Gem::Version, Gem::Requirement and the pre-release rule of
//     Gem::Dependency#match?.
//
// Where a tool accepts input only through a quirk (a regular expression that
// happens to match, an erased comparator), this package rejects it with an
// error instead: an expression it cannot read with certainty is refused, never
// guessed at. Every deliberate deviation is documented on the scheme.
//
// Versions and constraints come from repositories and registries, so every
// parser here reads untrusted input: inputs are bounded (MaxInputLength bytes,
// MaxTerms comparators or alternatives), numbers that do not fit an int64 are
// an error, and the parsers are hand-written scanners without backtracking.
// None of them panics on any input; each has a fuzz target.
package versions
