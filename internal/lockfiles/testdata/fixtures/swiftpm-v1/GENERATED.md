# swiftpm-v1

Generated 2026-11-12 by real SwiftPM in a throwaway container. Package.resolved is unedited tool
output. Package.swift was written by hand first and SwiftPM did not change it (sha256 compared
before and after). A one-line Sources/fixture-app/main.swift existed but is not part of the fixture.

- Tool: Swift 5.5.3 (swift-5.5.3-RELEASE), Swift Package Manager 5.5.3; git 2.17.1 from the image (Ubuntu 18.04.6).
- Image: `docker.io/library/swift:5.5` = `swift@sha256:38d0a66eff0022c0513595f4f218ee679196a4baa6581635e09a4191ca68da0b` (amd64 only).
- Input: `Package.swift` with `// swift-tools-version:5.5` and the old requirement syntax:
  `.exact("1.2.3")`, `from:`, `.branch("release/1.0")`, `.revision("…")`.

Command (resolution only, nothing built):

    podman run --rm -v <scratch>:/work -w /work/app docker.io/library/swift:5.5 swift package resolve

The format follows the root manifest's tools-version (below 5.6 → version 1), not the Swift
version: Swift 6.4.2 run on the same Package.swift (scratch copy) also wrote version 1, with the
same layout byte for byte apart from the resolved versions (it picked swift-algorithms 1.2.1,
swift-log 1.17.0, swift-numerics 1.1.1).

Notable features of Package.resolved:

- `{"object": {"pins": [...]}, "version": 1}`. JSON with 2-space indent and `"key": value` (no
  space before the colon, unlike versions 2 and 3). Trailing newline.
- A pin is `{"package", "repositoryURL", "state": {"branch", "revision", "version"}}`, with all three
  `state` keys always present and `null` where unused. No `identity`, `kind` or `location`; version
  1 cannot express a registry package.
- `package` is a name, here equal to the last path component of the URL without `.git`.
- 6 pins, sorted by `package`; swift-numerics is transitive (through swift-algorithms):
  - version pins (`"branch": null`): swift-algorithms 1.2.0 (f6919dfc…), swift-argument-parser
    1.2.3 (8f4d2753…, `.exact`), swift-log 1.5.4, swift-numerics 1.0.3 (e0ec0f5f…).
  - branch pin: swift-collections `"branch": "release/1.0"`, revision d029d9d3… (the branch head), `"version": null`.
  - revision pin: swift-system 836bc4557b74fe6d2660218d56e3ce96aff76574 with `"branch": null` and
    `"version": null`, although that commit is tag 1.1.1.
- swift-log 1.5.4 is an annotated tag: tag object 8263b980…, commit `1.5.4^{}` = e97a6fcb…; the pin
  records the commit. Its main Package.swift needs tools 5.6, but the tag also has
  `Package@swift-5.5.swift`, which SwiftPM 5.5 used.
- No content hashes.
