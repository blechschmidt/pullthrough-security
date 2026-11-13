# swiftpm-v3

Generated 2026-11-12 by real SwiftPM in a throwaway container. Package.resolved is unedited tool
output. Package.swift was written by hand first and SwiftPM did not change it (sha256 compared
before and after). A one-line Sources/fixture-app/main.swift existed but is not part of the fixture.

- Tool: Swift 6.4.2 (swift-6.4.2-RELEASE), Swift Package Manager 6.4.2; git 2.53.0 from the image (Ubuntu 26.04.1).
- Image: `docker.io/library/swift:6.4` = `swift@sha256:0384f00cf80f81064a907c249a0ad56a1648906f65075a95b1827e88de666e21`
- Input: `Package.swift` with `// swift-tools-version:6.0`.

Command (resolution only, nothing built):

    podman run --rm -v <scratch>:/work -w /work/app docker.io/library/swift:6.4 swift package resolve

What decides the format: the tools-version of the root manifest, not the Swift version. SwiftPM
6.4.2 (Sources/PackageGraph/ResolvedPackagesStore.swift) writes version 3 when the lowest root
tools-version is above 5.9, version 2 from 5.6 and version 1 below that. A first attempt with
`// swift-tools-version:5.9` on this same Swift 6.4.2 wrote `"version" : 2` and no `originHash`.

Notable features of Package.resolved:

- JSON in Apple's pretty-print style: 2-space indent, `"key" : value` (a space before the colon),
  keys sorted. Top level: `originHash`, `pins`, `"version" : 3`. Trailing newline.
- `originHash` (`337ac0fa…`) is the SHA-256 of the root manifest: `sha256sum Package.swift` gives
  exactly this value. Per SwiftPM's `computeResolvedFileOriginHash`, it hashes the manifest file of
  each root package followed by the location strings of root dependencies given on the command line
  (none here). SwiftPM uses it to notice a changed manifest. It is not a hash of any dependency.
- 6 pins, sorted by identity: 5 direct dependencies and swift-numerics, which comes in through
  swift-algorithms. Nothing marks a pin as direct or transitive.
- Every pin: `identity` (here the last path component of the URL, without `.git`),
  `"kind" : "remoteSourceControl"`, `location` (the URL as written in the manifest), `state`.
- `state` has three shapes:
  - version requirement (`exact:` or `from:`): `{revision, version}`. swift-argument-parser
    `exact: "1.8.2"` → 1.8.2; swift-log `from: "1.6.0"` → 1.17.0; swift-algorithms 1.2.1;
    swift-numerics 1.1.1.
  - `branch: "main"` (swift-collections): `{"branch" : "main", "revision" : "88754449…"}`, no
    `version`. 88754449… was main's head (`git ls-remote`), and also the commit of tag 1.7.6.
  - `revision:` (swift-system at its main head, a commit no tag names; checked with
    `git ls-remote`): `{"revision" : "762c819b0f6db16da85137079200d7d582b5a3de"}` only.
- `revision` is always a commit id. SwiftPM resolves a tag with `^{commit}`
  (Sources/SourceControl/GitRepository.swift, `resolveRevision(tag:)`). The four tags here are
  lightweight, so the revision is also what the tag ref names (checked with `git ls-remote`).
  swiftpm-v2 and swiftpm-v1 each contain an annotated tag, and there the revision is the commit,
  not the tag object.
- No content hash anywhere: a source-control pin is identified by its commit id only.
