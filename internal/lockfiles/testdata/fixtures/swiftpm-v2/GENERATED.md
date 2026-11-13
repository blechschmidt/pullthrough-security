# swiftpm-v2

Generated 2026-11-12 by real SwiftPM in a throwaway container. Package.resolved is unedited tool
output. Package.swift was written by hand first and SwiftPM did not change it (sha256 compared
before and after). A one-line Sources/fixture-app/main.swift existed but is not part of the fixture.

- Tool: Swift 5.9.2 (swift-5.9.2-RELEASE), Swift Package Manager 5.9.2; git 2.34.1 from the image (Ubuntu 22.04.5).
- Image: `docker.io/library/swift:5.9` = `swift@sha256:006635153a77dfc9d096dfc954b362d9017f1560d74c357100b50429bf5174c7`
- Input: `Package.swift` with `// swift-tools-version:5.9`. The refs were chosen so that SwiftPM 5.9
  can load their manifests: swift-argument-parser 1.8.2 needs tools 6.0, swift-collections' main
  6.4 and swift-system's current main commit 6.2, so this file pins argument-parser 1.6.1, the
  branch `release/1.1` and swift-system's tag 1.4.0 commit instead.

Command (resolution only, nothing built):

    podman run --rm -v <scratch>:/work -w /work/app docker.io/library/swift:5.9 swift package resolve

Version 2 is what any SwiftPM writes for a root manifest with tools-version 5.6 to 5.9: Swift 6.4.2
also wrote `"version" : 2` for a tools-version 5.9 manifest (see swiftpm-v3).

Notable features of Package.resolved:

- Same JSON style and pin shape as version 3 (`identity`, `kind`, `location`, `state`; `"key" : value`,
  2-space indent, keys sorted, trailing newline), but the top level is only `pins` and
  `"version" : 2`: no `originHash`.
- 6 pins, all `remoteSourceControl`; swift-numerics is transitive (through swift-algorithms).
- Version pins `{revision, version}`: swift-algorithms 1.2.1, swift-argument-parser 1.6.1
  (`exact:`), swift-log 1.6.4, swift-numerics 1.1.1.
- swift-log `from: "1.5.0"` stopped at 1.6.4 although 1.17.0 exists: newer manifests need a newer
  tools-version (1.7.0's needs 6.0) and SwiftPM skips versions it cannot load.
- swift-log 1.6.4 is an annotated tag. `git ls-remote` shows the tag object 0541b6f7… and the commit
  `1.6.4^{}` = ce592ae52f982c847a4efc0dd881cc9eb32d29f2. The pin records the commit.
- Branch pin swift-collections: `{"branch" : "release/1.1", "revision" : "c11818f3…"}` (the branch head).
- Revision pin swift-system: `{"revision" : "c8a44d836fe7913603e246acab7c528c2e780168"}`. That commit is
  what tag 1.4.0 names, yet the pin has no `version`: a revision pin has none even for a tagged
  commit (the same in swiftpm-v1).
- No content hashes.
