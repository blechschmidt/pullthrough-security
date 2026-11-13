# bazel-9

Generated 2026-11-12 by real Bazel on the host (linux/amd64). MODULE.bazel.lock is
unedited tool output. MODULE.bazel, the empty BUILD and .bazelversion were written by
hand first; Bazel did not change them.

- Tool: Bazel 9.3.2, the latest 9.x release (10.0.0 exists only as release candidates).
  Build time 2026-11-04 22:18:38 UTC. Binary sha256 2e14c55c298752d71e8a0bbd762665ffce5966c9ad00ec5d1a8b82a58e7bfa06,
  which equals the published `bazel-9.3.2-linux-x86_64.sha256`.
- Launcher: Bazelisk v1.30.0, the static `bazelisk-linux-amd64` release binary. Its sha256
  a248ae2b2b62b5baebb748f6fba7203bff1a27e5d01b55399a8406744cb539e8 equals the published
  `.sha256`. Bazelisk also checked the Bazel release signature.
- Command: scratch HOME, output root and Bazelisk cache, no rc files, no other environment.
  Nothing was built:

      env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=<scratch>/home TMPDIR=<scratch>/tmp LANG=C.UTF-8 \
        BAZELISK_HOME=<scratch>/bazelisk-home USE_BAZEL_VERSION=9.3.2 \
        bazelisk --nosystem_rc --nohome_rc --output_user_root=<scratch>/bazel-root \
        mod deps --lockfile_mode=update --allow_yanked_versions=rules_testing@0.0.5

- The dev dependency `rules_testing` 0.0.5 is a version the BCR has yanked, chosen on
  purpose so that `selectedYankedVersions` is not empty.
  - Without `--allow_yanked_versions`, Bazel stops with "Yanked version detected in your
    resolved dependency graph: rules_testing@0.0.5, ..." and writes no lock file.
  - A rerun with `--lockfile_mode=error` and the same flags succeeds and leaves the file
    byte-identical.
  - Error mode without the allow flag still fails, so the lock entry does not by itself
    permit the yanked version.

Notable features of MODULE.bazel.lock (51785 bytes, 2-space JSON, LF, trailing newline, no
absolute paths or user names):

- `"lockFileVersion": 28`, the same number Bazel 8.8.2 writes (see bazel-8). Top-level keys, in
  order: `lockFileVersion`, `registryFileHashes`, `selectedYankedVersions`, `moduleExtensions`,
  `facts`, `factsVersions`.
- `registryFileHashes` has 191 entries, sorted by URL. Each maps a registry file Bazel read
  to the lowercase hex SHA-256 of the bytes served at that URL:
  - `https://bcr.bazel.build/bazel_registry.json`, whose content is `{"mirrors": []}`;
  - 161 `https://bcr.bazel.build/modules/<name>/<version>/MODULE.bazel`;
  - 29 `https://bcr.bazel.build/modules/<name>/<version>/source.json`.

  Checked by downloading bazel_registry.json and the source.json files of platforms 1.1.0
  and rules_testing 0.0.5.
- Module name and version can be read from the URL path, but the MODULE.bazel entries also
  cover versions that were only looked at during resolution: 132 of the 161 are versions MVS
  did not select. platforms alone has 10 (0.0.4 … 1.1.0).
- The 29 `source.json` entries are exactly the 29 selected registry modules, compared against
  `bazel mod graph --include_builtin --output=json`. The built-in `bazel_tools` has no entry.
  Versions are Bazel module versions, not semver, for example `re2/2024-07-02.bcr.1`,
  `swift_argument_parser/1.3.1.2`, `zlib/1.3.1.bcr.5`.
- Only 5 of the 29 are below the root when edges into built-in modules are ignored:
  platforms 1.1.0, bazel_skylib 1.9.2, rules_testing 0.0.5, rules_license 1.0.0 and
  package_metadata 0.0.3. The other 24 are reachable only through Bazel's built-in
  `bazel_tools` module (protobuf 33.4, rules_java 9.1.0, rules_python 1.7.0, rules_swift 3.1.2,
  rules_kotlin 1.9.6 and others), so any lock written by this Bazel contains them.
- `selectedYankedVersions` is
  `{"rules_testing@0.0.5": "Mostly broken: https://github.com/bazelbuild/rules_testing/issues/33"}`:
  the key is `<name>@<version>` and the value is the yank reason from the registry's
  `modules/rules_testing/metadata.json`. metadata.json itself is never in `registryFileHashes`.
- The lock stores nothing else per module: no dependency edges, no dev-dependency flag
  (rules_testing looks like every other module), and no archive URL or digest. Those are in
  the hashed `source.json`.
  - platforms 1.1.0's source.json is
    `{"url": "https://github.com/bazelbuild/platforms/releases/download/1.1.0/platforms-1.1.0.tar.gz", "integrity": "sha256-261KI6vMphceR7ee3FO9akEGejt1+eixBGVrRZ/yUEY="}`.
    `integrity` is the SRI SHA-256 of the archive (checked by downloading it).
  - rules_testing 0.0.5's source.json also has `strip_prefix`, `patch_strip` and `patches`.
    `patches` maps `module_dot_bazel_version.patch` to the SRI SHA-256 of that file under
    `https://bcr.bazel.build/modules/rules_testing/0.0.5/patches/`.
- `moduleExtensions` has 4 entries, all from Bazel's built-in dependencies (demo uses no
  extension):
  - `@@pybind11_bazel+//:internal_configure.bzl%internal_configure_extension`
  - `@@rules_kotlin+//src/main/starlark/core/repositories:bzlmod_setup.bzl%rules_kotlin_extensions`
  - `@@rules_python+//python/extensions:config.bzl%config`
  - `@@rules_python+//python/uv:uv.bzl%uv`

  Canonical repo names use `+`. platforms' `host_platform` extension, used in platforms
  1.1.0's MODULE.bazel, is not recorded (bazel-6 records it).
- Each extension value has a single key here, `general`, which holds:
  - `bzlTransitiveDigest` and `usagesDigest`: base64 of 32-byte digests that Bazel computes over
    the extension's .bzl code and its usages. They are not digests of anything downloaded.
  - `recordedInputs`: strings of the form `REPO_MAPPING:<repo>,<apparent name> <canonical name>`
    or `FILE:<label> <hex SHA-256 of the file>`. The value in
    `FILE:@@pybind11_bazel+//MODULE.bazel e6f4c204...` equals the registry hash of
    `pybind11_bazel/2.12.0/MODULE.bazel`.
  - `generatedRepoSpecs`: repo name → `{"repoRuleId": "<.bzl label>%<rule>", "attributes": {...}}`.
- `generatedRepoSpecs` are where the lock records downloads that do not come from the
  registry:
  - 15 `http_archive` wheels from rules_python's `config` extension (`pypi__build` …
    `pypi__zipp`). `url` points at files.pythonhosted.org and `sha256` is the hex SHA-256 of
    that file; checked for pip-24.0-py3-none-any.whl against PyPI.
  - rules_kotlin: `rules_android` (`http_archive`, `urls` + `sha256`), ktlint (`http_file`,
    `urls` + `sha256`), and the Kotlin compiler and KSP repos (custom rules with `urls` + `sha256`).
  - pybind11: an `http_archive` with `urls` = `https://github.com/pybind/pybind11/archive/v2.12.0.zip`
    and no hash at all.
- `facts` and `factsVersions` are empty objects.
