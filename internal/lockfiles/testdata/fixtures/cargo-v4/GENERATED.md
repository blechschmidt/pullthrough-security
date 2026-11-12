# cargo-v4

Generated with cargo 1.97.1 (c980f4866 2026-06-30) on the host:

    CARGO_HOME=<scratch> cargo generate-lockfile

- `Cargo.lock` format `version = 4`.
- `itoa` 1.0.11 and `ryu` 1.0.18 (the latter through the path crate `helper`) come from
  crates.io (`registry+https://github.com/rust-lang/crates.io-index`) with a SHA-256 checksum.
- `semver` is a git dependency (`tag = "1.0.23"`), pinned to commit
  69efd3cc770ead273a06ad1788477b3092996d29; git sources carry no checksum.
- `fixture-app` and `helper` are workspace crates (no `source`), not dependencies.
