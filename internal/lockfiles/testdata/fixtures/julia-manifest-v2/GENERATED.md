# julia-manifest-v2

Generated 2026-11-12 by real Pkg in a throwaway container. Project.toml and Manifest.toml are both
written by Pkg (the project started empty) and were not edited.

- Tool: Julia 1.11.9 (its bundled Pkg).
- Image: `docker.io/library/julia:1.11` = `julia@sha256:8ac782116efde3df73938b5e2a74d35d9b426a479af0a5b27a207a77d0851d84`
- Why 1.11 and not the newest Julia: Pkg writes `manifest_format = "2.0"` for Julia < 1.13 only.
  Julia 1.13.3 writes `"2.1"`; that output is the fixture julia-manifest-v2.1 (same script).

Commands (precompilation switched off, scratch depot):

    podman run --rm -v <scratch>:/work -v <scratch>/depot:/depot -v <scripts>:/scripts:ro -w /work/proj \
      -e JULIA_DEPOT_PATH=/depot -e JULIA_PKG_PRECOMPILE_AUTO=0 \
      docker.io/library/julia:1.11 julia --startup-file=no --project=/work/proj /scripts/julia2.jl

with julia2.jl:

    using Pkg
    println(VERSION)
    Pkg.add("JSON")
    Pkg.add(url="https://github.com/JuliaLang/Example.jl", rev="82d1224c32990c0105898fa44009864f5648e98d")
    Pkg.add("Dates")
    Pkg.status()
    Pkg.status(; mode=Pkg.PKGMODE_MANIFEST)

Notable features of Manifest.toml:

- TOML. A `#` header line, then top-level `julia_version = "1.11.9"`, `manifest_format = "2.0"`,
  `project_hash`, and one `[[deps.<Name>]]` array-of-tables entry per package (14), sorted by name.
- `project_hash` (`75f7d929…`) is the SHA-1 Pkg computes over its own text of the project's direct
  dependencies (`project_resolve_hash` in Pkg's Types.jl). Recomputed: sha1 of the three sorted
  lines `Dates=<uuid>`, `Example=<uuid>`, `JSON=<uuid>` is exactly this value (the project has no
  `[compat]`). It is not a hash of Project.toml (`sha1sum` differs) or of anything downloaded; Pkg
  uses it to notice that the manifest is stale.
- Every entry has `uuid`. Registry packages (JSON 1.13.4, Parsers 3.0.6, PrecompileTools 1.2.1,
  Preferences 1.6.1, StructUtils 2.12.1) have `version` and `git-tree-sha1`; format 2.0 does
  not say which registry they came from.
- `git-tree-sha1` is the git tree object id (SHA-1) of the package's source tree at that version,
  not a commit and not a file hash. Checked: JSON's `06d90f69…` equals the `"1.13.4"` entry in
  General's J/JSON/Versions.toml and `git rev-parse 'v1.13.4^{tree}'` in JuliaIO/JSON.jl (v1.13.4
  is an annotated tag); Parsers 3.0.6 and PrecompileTools 1.2.1 also equal their General entries.
  The Pkg server serves the source tarball at `https://pkg.julialang.org/package/<uuid>/<git-tree-sha1>`
  (checked for JSON: 301 to a regional server, 302 to storage.julialang.net, 200, 152613 bytes).
- URL-tracked package Example 0.5.5: `repo-url = "https://github.com/JuliaLang/Example.jl"`,
  `repo-rev = "82d1224c32990c0105898fa44009864f5648e98d"` (the rev passed to `Pkg.add`; here a
  commit, it may also be a branch or tag name) and `git-tree-sha1 = "84ec6704…"`, the tree of
  that commit (checked with `git rev-parse`). The registered Example 0.5.5 has a different tree
  (`e1f0e1a8…` in General and `v0.5.5^{tree}`): the same name and version, other content.
- Stdlibs (Dates, Logging, Printf, Random, SHA, TOML, UUIDs, Unicode) have `uuid` and `version`
  (1.11.0, SHA 0.7.0, TOML 1.0.3) but no `git-tree-sha1` and no repo; they ship with Julia.
  Dates was added explicitly, the others are transitive.
- `deps` is a list of names (Pkg writes a name → uuid table instead when two packages in the
  manifest share a name; per Pkg 1.13's manifest.jl, not seen here).
- `[deps.JSON.weakdeps]` / `[deps.StructUtils.weakdeps]` and the `extensions` tables name weak
  dependencies (ArrowTypes, Serialization, DataFrames, Tables, …). None of them is locked: they
  have no `[[deps.X]]` entry.
- Project.toml lists the three direct dependencies in `[deps]` only. Pkg 1.11 writes no
  `[sources]` for the URL package (Pkg 1.13 does).
- LF line endings, trailing newline.
