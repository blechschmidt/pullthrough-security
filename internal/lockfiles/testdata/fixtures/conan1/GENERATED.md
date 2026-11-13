# conan1

Generated 2026-11-12 on the host with Conan 1.66.0, the latest 1.x on PyPI. It ran on CPython
3.12.3 in a fresh venv made with uv 0.11.14. Python 3.12 prints SyntaxWarnings for Conan 1's
regexes, which are harmless and were silenced with PYTHONWARNINGS=ignore. Nothing was built and no
binary was downloaded.

    export HOME=<scratch>/home CONAN_USER_HOME=<scratch>/conanhome
    conan profile new default --detect     # gcc 13, compiler.libcxx=libstdc++, Release, Linux x86_64
    conan config set general.revisions_enabled=1
    conan lock create --reference=zlib/1.2.13@ --lockfile-out=conan.lock
    cd consumer && conan lock create conanfile.txt -s compiler.version=11 --lockfile-out=conan.lock

`no-revisions/conan.lock` came from a second, fresh CONAN_USER_HOME with the same profile and the
same `--reference` command, but without `conan config set general.revisions_enabled=1`.

The remote is the default `conancenter` = https://center.conan.io, the frozen Conan 1
ConanCenter, which still served on 2026-11-12. `consumer/conanfile.txt` was written by hand. The
three `conan.lock` files are the tool's output, unedited.

Revisions:

- Revisions are off by default in 1.66. `conan config get general.revisions_enabled` answers
  `'revisions_enabled' doesn't exist in [general]`.
- With revisions off, the download log says `Downloaded recipe revision 0`. The lock then has
  `"revisions_enabled": false`, and `ref` has no `#rrev` (`"ref": "zlib/1.2.13"`).
- Running the consumer in scratch with revisions off also wrote every `prev` as `"0"`.

Layout (all three files):

- JSON with 1-space indent and no trailing newline; the file ends in `}`.
- Top level: `graph_lock` (with `nodes` and `revisions_enabled`), `"version": "0.4"`, and
  `profile_host`, which is the host profile as one `\n`-joined string, `[settings]` … `[env]`.
- `nodes` maps a node id string to a node. Node keys come in this order, and most are left out
  when empty: `ref`, `options`, `package_id`, `prev`, `python_requires`, `modified`, `requires`,
  `build_requires`, `path`, `context` (`GraphLockNode.serialize` in `conans/model/graph_lock.py`).
- `ref` is `name/version[@user/channel]#rrev`. `zlib/1.2.13@` (empty user/channel) is written
  without the `@`.
- `options` is a `\n`-separated `key=value` string. The consumer's options carry a `pkg:` prefix
  for dependencies, and cmake's is `""`.
- `requires` and `build_requires` are lists of node ids, not references.

`conan.lock` (`--reference`):

- It has a single node `"1"`: `zlib/1.2.13#4e74ebf1361fe6fb60326f473f276eb5`, package_id
  `c11224e931af7eb47df7c689b7ad7afc6b151bd9`, `context: "host"`.
- The virtual root that `--reference` creates is not written (RECIPE_VIRTUAL nodes are skipped),
  so ids start at `"1"`.
- There is no `prev` and no `requires`. The binary for the detected gcc 13 profile is "Missing".
  For Linux x86_64 gcc Release static, `conan search -q` lists ConanCenter v1 zlib/1.2.13 builds
  only for gcc 5, 7, 9 and 11.

`consumer/conan.lock` (`[requires] libpng/1.6.40, zlib/1.2.13`, `[tool_requires] cmake/3.27.9`):

- `-s compiler.version=11` was used so that the remote has binaries, which makes `prev` appear.
  `profile_host` records `compiler.version=11`. zlib's package_id is `dfbe50fe…` here and
  `c11224e9…` under gcc 13.
- Node `"0"` is the consumer: it has no `ref`, has `"path": "conanfile.txt"`,
  `requires: ["1", "2"]` and `build_requires: ["3"]`.
- `"1"` libpng/1.6.40#3e5bfaeeb94f87558582a88a3a1a7524 (`requires: ["2"]`), `"2"`
  zlib/1.2.13#4e74ebf1…, `"3"` cmake/3.27.9#e255e9c6cc3ac4856c44ad84476ec434. Each has
  `package_id` and `prev`.
- cmake has `context: "host"`: with a single profile, tool requirements live in the host context.
- libpng asks for `zlib/[>=1.2.11 <2]`. Conan warned that the consumer's zlib/1.2.13 overrode it.
  The lock shows only the result.

Hashes:

- rrev (recipe revision, default `revision_mode = "hash"`) is the MD5 of the
  `conanmanifest.txt` lines `"<path>: <md5 of file>\n"`, sorted by path, without the manifest's
  first line (the export timestamp). This is the same `summary_hash` as in Conan 2.
  - Recomputed from the cached manifests for zlib `4e74ebf1…`, libpng `3e5bfaee…` and cmake
    `e255e9c6…`. All match.
- `prev` (package revision) is the same summary hash over the binary package's
  `conanmanifest.txt`, which lists every file of the package (`conaninfo.txt`, headers, libs, …).
  - The package manifests were fetched with
    `conan get "<name>/<version>@#<rrev>:<package_id>" conanmanifest.txt -r conancenter --raw`,
    which downloads no binaries. libpng `f7e784d1…`, zlib `5accbbf3…` and cmake `d5526ae7…` all
    match.
  - Sort by path, not by whole line. cmake's 3282-entry manifest gives a different MD5 if sorted
    by line, because there are path prefixes like `bin/cmake` and `bin/cmake-gui`.
- `package_id` identifies the binary configuration. It is not checked here.
