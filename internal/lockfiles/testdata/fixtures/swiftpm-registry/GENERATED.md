# swiftpm-registry

Generated 2026-11-12 by real SwiftPM in a throwaway container against Tuist's public Swift package
registry (SE-0292), anonymously: no login, no token. Both Package.resolved files are unedited tool
output. Package.swift was written by hand first and SwiftPM did not change it (sha256 compared
before and after). `.swiftpm/configuration/registries.json` was written by
`swift package-registry set`; it holds only the registry URL (`"authentication" : {}`).

- Tool: Swift 6.4.2 (swift-6.4.2-RELEASE), Swift Package Manager 6.4.2.
- Image: `docker.io/library/swift:6.4` = `swift@sha256:0384f00cf80f81064a907c249a0ad56a1648906f65075a95b1827e88de666e21`
- Registry: https://tuist.dev/api/registry/swift
- Input: `Package.swift` (`// swift-tools-version:6.0`) with three registry dependencies:
  `.package(id: "apple.swift-argument-parser", exact: "1.8.2")`, `.package(id: "apple.swift-log", from: "1.6.0")`,
  `.package(id: "apple.swift-algorithms", from: "1.2.0")`.

Commands (resolution only, nothing built):

    podman run --rm -v <scratch>:/work -w /work/app docker.io/library/swift:6.4 sh -c \
      'swift package-registry set https://tuist.dev/api/registry/swift && swift package resolve -v'
    # replace-scm-with-registry/: same Package.swift and registries.json, in a fresh directory
    podman run --rm -v <scratch2>:/work -w /work/app docker.io/library/swift:6.4 \
      swift package resolve --replace-scm-with-registry

Notable features of Package.resolved:

- Version 3; `originHash` `57b62875…` = sha256 of Package.swift (checked), the same in both files.
- A registry pin is
  `{"identity" : "apple.swift-argument-parser", "kind" : "registry", "location" : "", "state" : {"version" : "1.8.2"}}`:
  the identity is the registry's `scope.name`, `location` is an empty string, and `state` holds only
  the version. No revision, no checksum, no registry URL: which registry serves it follows from
  registries.json (here the `[default]` registry).
- 3 registry pins (apple.swift-algorithms 1.2.1, apple.swift-argument-parser 1.8.2,
  apple.swift-log 1.17.0) and 1 source-control pin: swift-algorithms' own manifest names
  swift-numerics by URL, so it was cloned from GitHub and is pinned as `remoteSourceControl`
  (identity `swift-numerics`, revision 0c0290ff…, version 1.1.1). One file can mix both kinds.
- The archive checksum is elsewhere. The registry's release metadata
  (`GET …/apple/swift-argument-parser/1.8.2`) lists the source archive with `checksum`
  72e18cdb…; that is the sha256 of the 894771-byte `1.8.2.zip` (downloaded and checked). SwiftPM
  stored it, with the registry URL as `origin`, in `~/.swiftpm/security/fingerprints/apple.swift-argument-parser.json`
  inside the container (checked in a repeat run, whose Package.resolved was byte-identical), not in
  Package.resolved.
- Tuist's archives are unsigned: SwiftPM warned "source archive from https://tuist.dev/api/registry/swift is not signed".

Notable features of replace-scm-with-registry/Package.resolved:

- With `--replace-scm-with-registry`, SwiftPM mapped the URL dependency to the registry identity
  `apple.swift-numerics` and fetched it from the registry. Its pin gains a key the others lack:
  `{"identity" : "apple.swift-numerics", "kind" : "registry", "location" : "", "originalLocation" : "https://github.com/apple/swift-numerics.git", "state" : {"version" : "1.1.1"}}`.
- The other three pins and `originHash` are the same as in the top-level file.
