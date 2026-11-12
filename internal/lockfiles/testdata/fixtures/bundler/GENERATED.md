# bundler fixture — how it was generated

`Gemfile.lock` was written by real Bundler (2026-11-12, linux/amd64); it is not hand-made and must not be edited.

- Tool: Bundler 2.6.9, Ruby 3.3.13, RubyGems 3.5.22. The image's default Bundler 2.5.22 has no `bundle lock --add-checksums`, so Bundler 2.6.9 (latest 2.6.x) was installed inside the throwaway container first.
- Image: `ruby:3.3` = `ruby@sha256:2aa77cb4221aa5ab991b85ff1cd202d6ef74f2d1a578b6f8e7783a391b45dd68`
- Input: `Gemfile`

Commands, all in one container. Nothing was installed and no native extension was built. Bundler cloned rack-test from GitHub to read its gemspec. Version and help output, plus copies of the lock file after each step, are left out below:

    docker run --rm -v /mnt/HC_Volume_106716549/pt178/jvm:/work -w /work/bundler ruby:3.3 sh -c '
      set -e
      gem install bundler -v "~> 2.6.0" --no-document
      bundle lock
      bundle lock --add-platform x86_64-linux aarch64-linux
      bundle lock --add-checksums'

Notable features of `Gemfile.lock`:

- Sections in order: GIT, GEM, PLATFORMS, DEPENDENCIES, CHECKSUMS, BUNDLED WITH.
- Git gem rack-test pinned to `revision: 81a2ea15e107785d3692b81d7fa2bef969acc88f` with `tag: v2.1.0`; its spec depends on `rack (>= 1.3)`.
- That revision is the id of the annotated tag object `refs/tags/v2.1.0`, NOT a commit: the tagged commit is `867a6f1fc8e5d5ed79d8393f881f7e4c101edbfa` (`v2.1.0^{}`, checked with `git ls-remote` on 2026-11-12).
- GEM `remote: https://rubygems.org/` has a trailing slash that the Gemfile's source lacks.
- nokogiri 1.16.7 locked for 6 platforms as `nokogiri (1.16.7-<platform>)`: aarch64-linux, arm-linux, arm64-darwin, x86-linux, x86_64-darwin, x86_64-linux.
- No plain-`ruby` nokogiri variant is locked, so mini_portile2 is absent.
- The first `bundle lock` already locked all 6 platforms; `--add-platform x86_64-linux aarch64-linux` changed nothing (both were present).
- racc 1.8.1 is transitive (nokogiri needs `racc (~> 1.4)`) and is locked as the plain ruby gem (its java variant is not locked).
- DEPENDENCIES pins `(= x.y.z)`; `rack-test!` has no version, and `!` marks a gem from a non-rubygems (here GIT) source.
- rake is in `group :development` in the Gemfile, but the lock file records no groups.
- CHECKSUMS lines read `name (version[-platform]) sha256=<hex>`; all 9 match rubygems.org's published sha256 of the `.gem` file for that platform.
- Git gem line `rack-test (2.1.0)` in CHECKSUMS has no checksum.
- Indentation is significant: specs 4 spaces, their dependencies 6, `BUNDLED WITH` version (2.6.9) 3. LF, trailing newline.
