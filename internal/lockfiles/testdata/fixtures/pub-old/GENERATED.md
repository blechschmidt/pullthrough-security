# pub-old

Generated 2026-11-12 by real pub from Dart 2.18 in a throwaway container. pubspec.lock is
unedited tool output. pubspec.yaml (started from Dart 2.18's `dart create -t console` template)
and helper/pubspec.yaml were written by hand first, and pub did not change them (sha256 compared
before and after).

- Tool: Dart SDK 2.18.7 (stable) (Thu Jan 12 10:44:08 2023 +0000) on "linux_x64"; git 2.30.2 from the image.
- Image: `docker.io/library/dart:2.18` = `dart@sha256:ff4b8ee44567352ead890bc192699791c7574c67333b72598de830118c960a5c`
- Inputs: `pubspec.yaml`, `helper/pubspec.yaml` (a local package used as a path dependency).
- Why 2.18: it is the newest 2.x that writes no `sha256`. Dart 2.19.6
  (`dart@sha256:4b746768b82e2f650bb4b0bbec19f5da60d9649adb8d93d65f722028689f76c9`) already writes
  `sha256` and `url: "https://pub.dev"` (checked with a one-dependency probe project).

Commands (`dart --disable-analytics` was run first in each container):

    podman run --rm -v <scratch>:/work -w /work docker.io/library/dart:2.18 \
      dart create --no-pub -t console app
    # pubspec.yaml edited by hand: test removed; path, http, equatable (git), helper (path),
    # args (dev) and a dependency_overrides entry for meta added
    podman run --rm -v <scratch>:/work -w /work/app -e PUB_CACHE=/pubcache -v <scratch>/pub-old-cache:/pubcache \
      docker.io/library/dart:2.18 dart pub get

A first run had `meta: ^1.8.0` as the override, and pub 2.18 then locked meta 1.19.0 although
that version's pubspec requires Dart `^3.5.0`. The override was changed to `meta: 1.8.0`, the
lock file and `.dart_tool` deleted and `dart pub get` run again. This file is from that run.

Notable features of pubspec.lock:

- Same layout as current pub: two `#` header lines, `packages:` sorted by name, `sdks:` with
  `dart: ">=2.18.7 <3.0.0"`.
- No `sha256` anywhere: hosted entries are only `description: {name, url: "https://pub.dartlang.org"}`,
  `source: hosted`, `version`. The hosted URL is the old `https://pub.dartlang.org`, not `https://pub.dev`.
- 14 packages. `dependency:` is `"direct main"` (equatable, helper, http, path), `"direct dev"`
  (args, lints), `"direct overridden"` (meta 1.8.0) or `transitive` (async, collection,
  http_parser, source_span, string_scanner, term_glyph, typed_data).
- Git package equatable 2.0.5, asked for by commit: `source: git`,
  `description: {path: ".", ref: "2117551ff3054f8edb1a58f63ffe1832a8d25623",
  resolved-ref: "2117551ff3054f8edb1a58f63ffe1832a8d25623", url: "https://github.com/felangel/equatable.git"}`.
  `ref` equals `resolved-ref` because the ref is already a commit (the one tag v2.0.5 points
  to). `path: "."` means the package is at the repository root. Both hashes are quoted because
  they start with a digit.
- Path package helper 0.1.0: `source: path`, `description: {path: helper, relative: true}`.
- LF line endings, trailing newline.
