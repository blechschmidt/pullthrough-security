# pub

Generated 2026-11-12 by real pub (Dart SDK) in a throwaway container. pubspec.lock is unedited
tool output. pubspec.yaml (started from `dart create -t console`'s template) and
helper/pubspec.yaml were written by hand first, and pub did not change them (sha256 compared
before and after).

- Tool: Dart SDK 3.14.0 (stable) (Wed Nov 4 16:28:39 2026 -0800) on "linux_x64"; git 2.47.3 from the image.
- Image: `docker.io/library/dart:stable` = `dart@sha256:754aaf779c07a44017823fcb0e972f92d8053a9631531cc4e425053036efcb85`
- Inputs: `pubspec.yaml`, `helper/pubspec.yaml` (a local package used as a path dependency).

Commands (`dart --disable-analytics` was run first in each container; it does not affect the output):

    podman run --rm -v <scratch>:/work -w /work docker.io/library/dart:stable \
      dart create --no-pub -t console app
    # pubspec.yaml edited by hand: test removed; http, characters (git), helper (path),
    # args (dev) and a dependency_overrides entry for meta added
    podman run --rm -v <scratch>:/work -w /work/app -e PUB_CACHE=/pubcache -v <scratch>/pub-cache:/pubcache \
      docker.io/library/dart:stable dart pub get

Notable features of pubspec.lock:

- YAML with two `#` header lines, then `packages:` (keys sorted by name) and `sdks:` with
  `dart: ">=3.14.0 <4.0.0"` only (no `flutter:` key).
- 15 packages. `dependency:` is `"direct main"` (characters, helper, http, path), `"direct dev"`
  (args, lints), `"direct overridden"` (meta, named in `dependency_overrides`; http also depends
  on it) or `transitive` (async, collection, http_parser, source_span, string_scanner,
  term_glyph, typed_data, web).
- Hosted packages (13): `source: hosted`, `description: {name, sha256, url: "https://pub.dev"}`,
  `version: "<quoted>"`. `sha256` is the SHA-256 of the package's `.tar.gz` archive as pub.dev
  serves it. Checked for http 1.6.0 and args 2.7.0: sha256 of the file downloaded from
  `https://pub.dev/api/archives/<name>-<version>.tar.gz` equals the lock value, and so does the
  `archive_sha256` in `https://pub.dev/api/packages/<name>/versions/<version>`.
- Quoting varies by value: pub double-quotes a string unless it looks like a plain identifier.
  A sha256 is quoted when it starts with a digit (9 of the 13, e.g. http's `"87721a4a…"`) and
  bare when it starts with a letter (args `d0481093…`). `dependency: transitive` and
  `source: hosted` are bare, `"direct main"` and versions are quoted.
- Git package characters 1.4.1 from the dart-lang/core monorepo: `source: git`,
  `description: {path: "pkgs/characters", ref: "characters-v1.4.1",
  resolved-ref: b59ecf4ceebe6153e1c0166b7c9a7fdd9458a89d, url: "https://github.com/dart-lang/core.git"}`.
  `ref` is what pubspec.yaml asked for (a lightweight tag), `resolved-ref` is the commit it
  names (checked: `git cat-file -t` says commit). `path` is the package's directory inside the
  repository. A git package has no content hash.
- Path package helper 0.1.0: `source: path`, `description: {path: helper, relative: true}`;
  its version comes from helper/pubspec.yaml. Nothing is downloaded for it.
- No `sdk`-source package: that needs the Flutter SDK (`flutter: {sdk: flutter}`).
- LF line endings, trailing newline.
