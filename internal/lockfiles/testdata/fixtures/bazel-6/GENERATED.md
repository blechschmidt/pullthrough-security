# bazel-6

Generated 2026-11-12 by real Bazel on the host (linux/amd64). MODULE.bazel.lock is
unedited tool output. MODULE.bazel (the same as in bazel-9, bazel-8 and bazel-7), the empty
BUILD and .bazelversion were written by hand first; Bazel did not change them. Bazel 6.6.0
needed no WORKSPACE file.

- Tool: Bazel 6.6.0, the latest 6.x release. Build time 2026-01-21 18:36:24 UTC. Binary sha256
  31a97fd23503f8a3dc50b6c9232cc513fb7cdd1c4a80d4d598673c60ff77b6f3, which equals the published
  `bazel-6.6.0-linux-x86_64.sha256`.
- Launcher: Bazelisk v1.30.0 (static release binary, sha256 a248ae2b…39e8, equal to the
  published `.sha256`). Bazelisk also checked the Bazel release signature.
- Command: as for bazel-7, plus `--enable_bzlmod` and `--lockfile_mode=update`. With these
  flags Bazel 6.6.0 writes a lock file. Nothing was built:

      env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=<scratch>/home TMPDIR=<scratch>/tmp LANG=C.UTF-8 \
        BAZELISK_HOME=<scratch>/bazelisk-home USE_BAZEL_VERSION=6.6.0 \
        bazelisk --nosystem_rc --nohome_rc --output_user_root=<scratch>/bazel-root \
        mod deps --enable_bzlmod --lockfile_mode=update --allow_yanked_versions=rules_testing@0.0.5

- A rerun with `--lockfile_mode=error` and the same flags succeeds and leaves the file
  byte-identical. The dev dependency `rules_testing` 0.0.5 is yanked in the BCR, so that the
  lock records the allowance.

Notable features of MODULE.bazel.lock (74741 bytes, 2-space JSON, LF, trailing newline, no
absolute paths or user names). This is the old format: a resolved module graph instead of
`registryFileHashes`.

- `"lockFileVersion": 3`. Top-level keys, in order: `lockFileVersion`, `moduleFileHash`,
  `flags`, `localOverrideHashes`, `moduleDepGraph`, `moduleExtensions`. There are no
  `registryFileHashes` and no `selectedYankedVersions`.
- `moduleFileHash` is the hex SHA-256 of the root MODULE.bazel (checked).
- `flags` records the command-line state that affects resolution:
  - `cmdRegistries`: `["https://bcr.bazel.build/"]`;
  - `cmdModuleOverrides`: `{}`;
  - `allowedYankedVersions`: `["rules_testing@0.0.5"]`, from the flag;
  - `envVarAllowedYankedVersions`: `""`;
  - `ignoreDevDependency`: `false`;
  - `directDependenciesMode`: `"WARNING"`;
  - `compatibilityMode`: `"ERROR"`.
- `localOverrideHashes` is `{"bazel_tools": "0cc38516…"}`: the hex SHA-256 of the
  `bazel_tools` MODULE.bazel embedded in this Bazel. It equals
  `<install base>/embedded_tools/MODULE.bazel`.
- `moduleDepGraph` has 14 entries in breadth-first order from the root, not sorted. Keys are `<root>`,
  `<name>@<version>`, and `bazel_tools@_` / `local_config_platform@_` for the built-ins, whose
  `version` is `""`.
  - Only selected versions appear, one per module name.
  - `deps` maps repo name → selected key. rules_testing 0.0.5 asks for platforms 0.0.6, yet
    its `deps.platforms` is `"platforms@1.1.0"`.
  - Each entry has, in order: `name`, `version`, `key`, `repoName`,
    `executionPlatformsToRegister`, `toolchainsToRegister`, `extensionUsages`, `deps`, and
    `repoSpec` for the 11 registry modules.
  - The 11 registry modules are platforms 1.1.0, bazel_skylib 1.9.2, rules_testing 0.0.5,
    package_metadata 0.0.3, rules_license 1.0.0, rules_cc 0.0.9, rules_java 5.5.1,
    rules_proto 4.0.0, rules_python 0.4.0, protobuf 3.19.6 and zlib 1.2.13. The last six come
    from built-in `bazel_tools`.
- `repoSpec` holds what v13/v28 keep in the registry's source.json: `bzlFile`
  (`@bazel_tools//tools/build_defs/repo:http.bzl`), `ruleClassName` (`http_archive`) and
  `attributes`. Every module's name, version, archive URL and digest are in the lock.
  `attributes` contains:
  - `name`: `<name>~<version>`, e.g. `rules_testing~0.0.5`. platforms is the exception: its
    canonical name is plain `platforms`.
  - `urls`: a one-element list holding source.json's `url`.
  - `integrity`: SRI SHA-256 of the archive, equal to source.json's `integrity`. Checked by
    downloading the platforms 1.1.0 and bazel_skylib 1.9.2 archives.
  - `strip_prefix`: `""` for 5 modules (platforms, bazel_skylib, rules_license, rules_java,
    rules_python). package_metadata's is `supply-chain-0.0.3/metadata`.
  - `remote_patches`: patch URL under `https://bcr.bazel.build/modules/<name>/<version>/patches/`
    → SRI SHA-256 of the patch file (checked for rules_testing's). Empty `{}` for unpatched
    modules.
  - `remote_patch_strip`.
- Which registry a module came from is not recorded per module. Only `flags.cmdRegistries`
  and the patch URLs of patched modules show it.
- No registry file (MODULE.bazel, source.json) is hashed, and there is no yank information
  beyond `flags.allowedYankedVersions`.
- There is no dev-dependency marker. `rules_testing` sits in the root's `deps` like the other
  two; the root entry also lists `bazel_tools` and `local_config_platform`.
- `moduleExtensions` has 8 entries, keyed `@<canonical repo name>//<package>:<file>.bzl%<extension>`
  with a single `@`:
  - `@bazel_tools//tools/cpp:cc_configure.bzl%cc_configure_extension`, plus four more from
    bazel_tools (android tools, xcode, sh, coverage tools);
  - `@platforms//host:extension.bzl%host_platform`;
  - `@rules_java~5.5.1//java:extensions.bzl%toolchains`;
  - `@rules_python~0.4.0//bzlmod:extensions.bzl%pip_install`.
- Each extension value is `{"general": {"bzlTransitiveDigest", "accumulatedFileDigests": {}, "envVariables": {}, "generatedRepoSpecs"}}`.
  `generatedRepoSpecs` maps repo name → `{bzlFile, ruleClassName, attributes}`, and
  `attributes.name` is the full canonical repo name, e.g.
  `bazel_tools~remote_coverage_tools_extension~remote_coverage_tools`.
- Downloads recorded there, all with `sha256` (hex SHA-256 of the downloaded file):
  - 31 `http_archive` repos:
    - 23 from rules_java's `toolchains`, e.g. `remotejdk11_linux` with `urls` on
      mirror.bazel.build and cdn.azul.com and a `strip_prefix`;
    - 6 wheels from rules_python 0.4.0's `pip_install`;
    - `android_tools`;
    - `remote_coverage_tools` (coverage_output_generator-v2.6.zip, checked).
  - One `http_jar`: `android_gmaven_r8`, with `url` r8-8.0.40.jar on maven.google.com.

  The other repos (`cc_autoconf`, `cc_autoconf_toolchains`, `sh_config`, `xcode_autoconf`,
  `host_platform_repo`, 17 `_toolchain_config`, `_local_java_repository_rule`) have no URL or
  hash attributes.
