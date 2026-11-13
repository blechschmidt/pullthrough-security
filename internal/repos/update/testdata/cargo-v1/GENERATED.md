# cargo-v1

Hand-written in Cargo's original lock format (before Rust 1.41: no `version` key, every dependency
spelled "name version (source)", checksums in `[metadata]` keyed "checksum name version (source)"),
for the crates and checksums of cargo-v4: before/ as cargo-v4/before, after/ as cargo-v4/after.

Checked with real cargo 1.97.1 in a copy of the cargo-v4 workspace: `cargo fetch --locked` accepts
both files (downloading the crates and checking each against its checksum) and leaves them as they
are, `cargo metadata --locked --offline` resolves itoa 1.0.10 / ryu 1.0.17 from before/ and
itoa 1.0.11 / ryu 1.0.18 from after/; with one digit of a checksum changed, `cargo fetch --locked`
fails ("unable to verify that `itoa v1.0.11` is the same as when the lockfile was generated").
