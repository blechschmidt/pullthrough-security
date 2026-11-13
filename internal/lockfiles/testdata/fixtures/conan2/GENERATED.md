# conan2

Generated 2026-11-12 on the host with Conan 2.34.0, the latest on PyPI (uploaded 2026-10-28). It
ran on CPython 3.12.3 in a fresh venv made with uv 0.11.14, with an empty HOME and CONAN_HOME:

    export HOME=<scratch>/home CONAN_HOME=<scratch>/conanhome
    conan profile detect      # gcc 13, libstdc++11, gnu17, Release, Linux x86_64
    conan export fixture-pyreq --user=acme --channel=stable
    conan lock create .

The remote is the default `conancenter` = https://center2.conan.io. Nothing was built.

`conanfile.py` and `fixture-pyreq/conanfile.py` were written by hand. `conan.lock` is the tool's
output, unedited.

Why a conanfile.py: the requested `--build-require=cmake/3.28.1` does not exist in that form. In
2.34 `--build-require` is a boolean flag ("Whether the provided reference is a build-require"), and
tool requirements are passed with `--tool-requires`. A conanfile.py is also the only way to have a
`python_requires`. The consumer declares
`requires = "zlib/1.3.1", "fmt/10.2.1"`, `tool_requires = "cmake/3.28.1"` and
`python_requires = "fixture-pyreq/0.1@acme/stable"`. That python_requires is a local recipe
exported into the cache only; it is not on any remote.

`conan.lock`:

- JSON, 4-space indent, LF, trailing newline. The keys, in order, are `"version": "0.5"`,
  `requires`, `build_requires`, `python_requires` and `config_requires`.
- The four lists are always written, even when empty (`"config_requires": []`). An `overrides` key
  appears only when there are overrides; there are none here. Source:
  `conan/internal/model/lockfile.py`.
- Each item is a string `name/version[@user/channel]#<rrev>%<timestamp>`:
  - `requires`: the host-context graph nodes, `zlib/1.3.1#cac0f6daea041b0ccf42934163defb20%1765284699.337`
    and `fmt/10.2.1#15db2a3ea0646365bf05a6f50369ac59%1785754570.436`.
  - `build_requires`: the build-context nodes, from `tool_requires`:
    `cmake/3.28.1#92f79424d7b65b12a84a2180866c3a78%1703679314.116`.
  - `python_requires`: `fixture-pyreq/0.1@acme/stable#9dad71aa723229fbf54c68d975a01158%1794524042.1009889`.
    This is the only entry with `@user/channel`.
- Each list is sorted in descending order (`reversed(sorted(...))`), so zlib comes before fmt.
- The lists are flat. There are no dependency edges, options or settings, and no package ids or
  package revisions, so the lock does not pin binaries. `lock create` asked the remote about
  binaries: its output lists `zlib/1.3.1#cac0…:c81087b0…#d3a7706a…` as "Download". It did not
  download them, and the lock keeps none of that.
- The hidden flag `--lockfile-packages` (`help=argparse.SUPPRESS`) changes the item shape to
  `["<ref>", {"<package_id>": "<prev>"}]`. For example
  `["zlib/1.3.1#cac0…%1765284699.337", {"c81087b06d1a5beef0ad711fc32d45f7a425a8f3": "d3a7706ae25c74b78bafbb0b63cb5dcf"}]`.
  python_requires stay plain strings. Conan prints
  `ERROR: The --lockfile-packages arg is private and shouldn't be used` but still writes the file.
  This was tried in scratch and is not kept.
- `%<timestamp>` is the revision's creation time on the remote, in Unix seconds as a float. It
  equals the `timestamp` from `conan list "<ref>#*" -r conancenter`:
  - zlib `cac0f6…` 2025-12-09T12:51:39.337Z, fmt `15db2a…` 2026-08-03, cmake `92f794…` 2023-12-27.
  - For the locally exported python_requires it is the local export time with full float precision
    (`1794524042.1009889` = 2026-11-12T22:54:02Z).
- Each locked rrev is the newest revision on the remote. zlib/1.3.1 has 4 revisions, fmt/10.2.1 has
  5 and cmake/3.28.1 has 1.
- The rrev (recipe revision) under the default `revision_mode = "hash"` is
  `FileTreeManifest.summary_hash`:
  - It is the MD5 of the lines `"<path>: <md5 of file>\n"` for every exported file, sorted by path.
    The files are `conanfile.py`, `conandata.yml`, and exported sources as `export_source/<path>`.
  - That equals the text of `conanmanifest.txt` minus its first line, which is the export timestamp.
    Source: `_calc_revision` in `conan/internal/api/export.py` and `conan/internal/model/manifest.py`.
  - Sort by path, not by whole line: the two orders differ when one path is a prefix of another.
  - All 4 rrevs were recomputed from the manifests in the cache and match.
  - The md5s listed for `conanfile.py` and `conandata.yml` match the downloaded files. The
    `export_source/` patches are not downloaded by `lock create`.
  - The rrev is not a hash of any downloadable archive such as `conan_export.tgz`.
- `lock create` downloaded only the recipe files: `conanfile.py`, `conanmanifest.txt` and
  `conan_export.tgz`, which holds just `conandata.yml`. It downloaded no sources and no binaries.
- The cmake/3.28.1 recipe has no requirements of its own. Its `conandata.yml` points at Kitware's
  prebuilt tarballs on cmake.org.
