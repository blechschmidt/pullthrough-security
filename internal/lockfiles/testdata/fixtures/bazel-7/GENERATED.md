# bazel-7

Generated 2026-11-12 by real Bazel on the host (linux/amd64). MODULE.bazel.lock is
unedited tool output. MODULE.bazel (the same as in bazel-9, bazel-8 and bazel-6), the empty
BUILD and .bazelversion were written by hand first; Bazel did not change them. Bazel 7 needed
no WORKSPACE file.

- Tool: Bazel 7.7.2, the latest 7.x release. Build time 2026-10-23 17:47:56 UTC. Binary sha256
  f7b8c4e72f8776f6a352fbe699cc1de381342b5e7e0ad1f34d72c5a9b163288c, which equals the published
  `bazel-7.7.2-linux-x86_64.sha256`.
- Launcher: Bazelisk v1.30.0 (static release binary, sha256 a248ae2b…39e8, equal to the
  published `.sha256`). Bazelisk also checked the Bazel release signature.
- Command: scratch HOME, output root and Bazelisk cache, no rc files, no other environment.
  Nothing was built:

      env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=<scratch>/home TMPDIR=<scratch>/tmp LANG=C.UTF-8 \
        BAZELISK_HOME=<scratch>/bazelisk-home USE_BAZEL_VERSION=7.7.2 \
        bazelisk --nosystem_rc --nohome_rc --output_user_root=<scratch>/bazel-root \
        mod deps --lockfile_mode=update --allow_yanked_versions=rules_testing@0.0.5

- The dev dependency `rules_testing` 0.0.5 is yanked in the BCR, chosen on purpose so that
  `selectedYankedVersions` is not empty. A rerun with `--lockfile_mode=error` and the same
  flags succeeds and leaves the file byte-identical.

Notable features of MODULE.bazel.lock (106821 bytes, 2-space JSON, LF, trailing newline, no
absolute paths or user names):

- `"lockFileVersion": 13`. Top-level keys, in order: `lockFileVersion`, `registryFileHashes`,
  `selectedYankedVersions`, `moduleExtensions`. There is no `facts`.
- `registryFileHashes` has the same meaning as in v28 (bazel-8, bazel-9): URL → lowercase hex
  SHA-256 of the bytes served there. It has 68 entries, sorted by URL:
  - `https://bcr.bazel.build/bazel_registry.json`;
  - 47 `.../modules/<name>/<version>/MODULE.bazel`;
  - 20 `.../modules/<name>/<version>/source.json`.

  Checked by downloading: bazel_registry.json, rules_testing 0.0.5 source.json, and
  bazel_skylib 1.9.2 MODULE.bazel.
- 27 of the 47 MODULE.bazel entries are versions MVS did not select. platforms has 7
  (0.0.4 … 1.1.0).
- The 20 source.json entries are exactly the 20 selected registry modules, per
  `bazel mod graph --include_builtin --output=json`. The built-ins `bazel_tools` and
  `local_config_platform` are not in the lock.
- Versions include `rules_proto/5.3.0-21.7`, `upb/0.0.0-20220923-a547704` and
  `zlib/1.3.1.bcr.3`.
- Only 5 of the 20 are below the root when edges into built-in modules are ignored: platforms
  1.1.0, bazel_skylib 1.9.2, rules_testing 0.0.5, rules_license 1.0.0 and package_metadata
  0.0.3. The other 15 are Bazel's built-in dependencies (protobuf 21.7, rules_java 7.6.5,
  rules_python 0.22.1, rules_jvm_external 4.4.2 and others).
- `selectedYankedVersions` is
  `{"rules_testing@0.0.5": "Mostly broken: https://github.com/bazelbuild/rules_testing/issues/33"}`.
- As in v28, the lock has no per-module data besides these URLs: no dependency edges, no
  dev-dependency flag, and no archive URL or digest. Those are in the hashed `source.json`
  (`url`, `integrity` = SRI SHA-256 of the archive, optional `strip_prefix`/`patches`/`patch_strip`).
  For example, rules_jvm_external 4.4.2's source.json has
  `"url": "https://github.com/bazelbuild/rules_jvm_external/archive/refs/tags/4.4.2.zip"`.
- `moduleExtensions` has 4 entries, all from built-in dependencies, in this order (not plain
  string order). Canonical repo names use `~`, not `+`.
  - `@@rules_jvm_external~//:extensions.bzl%maven`
  - `@@rules_jvm_external~//:non-module-deps.bzl%non_module_deps`
  - `@@rules_python~//python/extensions:python.bzl%python`
  - `@@rules_python~//python/extensions/private:internal_deps.bzl%internal_deps`
- Each value is `{"general": {...}}`. Its keys, in order, differ from v28:
  - `bzlTransitiveDigest` and `usagesDigest`: base64, Bazel-internal, not digests of downloads.
  - `recordedFileInputs`: label → hex SHA-256 of the file. The value for
    `@@rules_jvm_external~//rules_jvm_external_deps_install.json` equals the file at tag 4.4.2.
  - `recordedDirentsInputs` and `envVariables`: `{}` in all four.
  - `generatedRepoSpecs`: repo name → `{"bzlFile": ..., "ruleClassName": ..., "attributes": {...}}`.
    v28 uses a single `repoRuleId` instead.
  - `recordedRepoMappingEntries`: arrays `[<repo>, <apparent name>, <canonical name>]`.
- Downloads recorded in `generatedRepoSpecs` (not from the registry):
  - `maven`: 74 `http_file` repos for Maven jars, each with:
    - `urls`: repo1.maven.org first, then maven.google.com;
    - `sha256`: hex SHA-256 of the jar (gson-2.9.0.jar checked);
    - `downloaded_file_path`, e.g. `v1/https/repo1.maven.org/maven2/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar`.

    It also has two `coursier_fetch` and one `pinned_coursier_fetch` repo, which have no URL.
  - `internal_deps`: 29 `http_archive` wheels from files.pythonhosted.org. `sha256` is the hex
    SHA-256 of the wheel (build-0.9.0-py3-none-any.whl checked against PyPI).
    - 14 give the address as `url` (a string).
    - 15 give it as `urls` (a list): the `pypi__coverage_*` wheels for 15 Python/platform
      combinations. These also carry `patches: ["@@rules_python~//python/private:coverage.patch"]`
      and `patch_args`, so the repo content is not the wheel as downloaded.
  - `non_module_deps`: `io_bazel_rules_kotlin` (`http_archive`, `urls` + `sha256`).
  - `python`: `pythons_hub`, which has no URL.
