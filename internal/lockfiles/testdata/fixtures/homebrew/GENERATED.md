# homebrew

Generated 2026-11-12 with Homebrew 4.4.8 and the homebrew/bundle tap at commit
8ae4e7f364bf8736e15914a3b6c76cd157deccb8 (2024-11-25), in podman on linux/amd64. Neither file was
edited afterwards; `Brewfile` is the hand-written input.

- Image: `docker.io/homebrew/brew:4.4.8` =
  `docker.io/homebrew/brew@sha256:34e0c5c56a555b1322e82b51ac4c1ba0f3a605bb02bf2835eb724f25aeaa2fd6`
  (Ubuntu 22.04.5, Homebrew 4.4.8, homebrew/core tapped at 5d3a32ca564a4da2ac86351c14e6773045490cc4).
- Why so old: `brew bundle` stopped writing `Brewfile.lock.json` with Homebrew/homebrew-bundle#1509
  (commit f92c362bc7995f98061eb0736c19c60e39a40651, "Remove `Brewfile.lock.json` generation.",
  merged 2024-11-27). 8ae4e7f is its parent. The file was introduced by
  8d23c65b8ffecf246161f19e0c7cbc19114d68d1 ("Write Brewfile.lock.json files", 2019-11-11).
  After the removal `--no-lock` is a hidden no-op. The tap was deprecated on 2025-03-19 and is archived;
  `brew bundle` now ships with Homebrew/brew.

Commands, as user linuxbrew in one container, with the directory holding only `Brewfile` mounted at
/work (version, `brew config` and `brew list` output left out):

    export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_INSTALL_CLEANUP=1
    brew tap homebrew/bundle
    git -C "$(brew --repository homebrew/bundle)" checkout -q 8ae4e7f364bf8736e15914a3b6c76cd157deccb8
    cd /work
    brew bundle

`HOMEBREW_NO_AUTO_UPDATE` stops brew from updating the tap back to its archived master, which no
longer writes the file. The formulae came from the JSON API (formulae.brew.sh) on 2026-11-12, so the
versions and bottle tags are 2026's: the tags include `arm64_tahoe` and `arm64_golden_gate`, macOS
releases that came after the lock file was removed. brew installed hello 2.12.3, jq 1.8.2 and
gnupg@1.4 1.4.23_1, plus the dependencies oniguruma 6.9.10 and zlib-ng-compat 2.3.3_1.

Notable features of `Brewfile.lock.json`:

- JSON with 2-space indentation (`JSON.pretty_generate`), LF, trailing newline. Two top-level keys:
  `entries` and `system`.
- `entries` has one object per entry type, here `tap` then `brew` (the order they first appear in the
  Brewfile). Only Brewfile entries are recorded; the dependencies oniguruma and zlib-ng-compat are not.
- `entries.tap.<name>.revision` is the tap's git HEAD: homebrew/bundle
  8ae4e7f364bf8736e15914a3b6c76cd157deccb8, homebrew/core 5d3a32ca564a4da2ac86351c14e6773045490cc4
  (recorded although the formulae came from the API).
- `entries.brew.<name>.version` is the installed keg's version, with a formula revision as `_N`:
  `2.12.3`, `1.8.2`, `1.4.23_1`. The bottle rebuild (1 for all three) is not part of it.
- `entries.brew.<name>.bottle` holds `rebuild` (an integer), `root_url`
  (`https://ghcr.io/v2/homebrew/core`) and `files`: one object per bottle tag of the formula, for every
  platform, not just the one installed: 6 tags for hello, 7 for jq and gnupg@1.4.
- Each file has `cellar`, `url` and `sha256`. `cellar` is `:any` or `:any_skip_relocation` (a Ruby
  symbol, written with its colon) or a path: `/opt/homebrew/Cellar`, `/usr/local/Cellar`,
  `/home/linuxbrew/.linuxbrew/Cellar`.
- `url` is `<root_url>/<repository>/blobs/sha256:<sha256>`. The repository is the formula name with `@`
  replaced by `/`: gnupg@1.4 is at `https://ghcr.io/v2/homebrew/core/gnupg/1.4/blobs/sha256:…`.
- `sha256` is the SHA-256 of the bottle `.tar.gz`, which is also the GHCR blob digest. Checked for
  hello's x86_64_linux file: the blob downloaded from its `url` is a gzip tarball with that SHA-256, and
  the OCI index `ghcr.io/homebrew/core/hello:2.12.3-1` lists it as `sh.brew.bottle.digest` of the
  manifest `2.12.3.x86_64_linux.1`.
- `system.linux."Ubuntu 22.04.5 LTS"` records `HOMEBREW_VERSION` 4.4.8, `HOMEBREW_PREFIX`,
  `"Homebrew/homebrew-core": "api"` and `GCC` 11.4.0. Without the API, the homebrew-core value is that
  tap's commit; on macOS the key is `system.macos.<codename>` with `CLT`, `Xcode` and `macOS` versions
  instead of `GCC`.
- No `cask`, `mas`, `whalebrew` or `vscode` entries. On Linux, homebrew-bundle skips cask and mas
  entries and the homebrew/cask tap, so they could not appear here.
