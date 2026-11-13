# cargo-v3

Generated 2026-11-13 by real cargo 1.97.1 (c980f4866 2026-06-30) on the host, scratch CARGO_HOME.
Unedited tool output.

The workspace (Cargo.toml, crates/helper/Cargo.toml) depends on itoa 1 and, renamed, on itoa 0.4
— so the lock file lists two crates named itoa and spells dependencies on them `"itoa 1.0.10"` —
on memchr, and (through helper) on ryu.

    cargo generate-lockfile
    cargo update -p itoa@1 --precise 1.0.10
    cargo update -p ryu --precise 1.0.17
    cargo update -p memchr --precise 2.7.1      # before/Cargo.lock
    cargo update -p itoa@1.0.10 --precise 1.0.11
    cargo update -p ryu --precise 1.0.18        # after/Cargo.lock

Cargo moved the versions, the checksums and the `"itoa 1.0.10"` dependency entries, nothing else.

Both manifests declare `rust-version = "1.70"`, for which cargo writes lock format `version = 3`.
