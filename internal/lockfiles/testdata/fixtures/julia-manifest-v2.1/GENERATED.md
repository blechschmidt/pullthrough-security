# julia-manifest-v2.1

Extra case (not in the requested list): the manifest format the current Julia writes. Generated
2026-11-12 by real Pkg in a throwaway container. Project.toml and Manifest.toml are both written by
Pkg (the project started empty) and were not edited.

- Tool: Julia 1.13.3 (its bundled Pkg), the newest stable release on Docker Hub that day.
- Image: `docker.io/library/julia:1.13` = `julia@sha256:5359aeb77674c96611149652f78ab10ee7fcec7a2b5556a662306ced12dbc5e5`
- Same command and script as julia-manifest-v2, with `julia:1.13`:

      podman run --rm -v <scratch>:/work -v <scratch>/depot:/depot -v <scripts>:/scripts:ro -w /work/proj \
        -e JULIA_DEPOT_PATH=/depot -e JULIA_PKG_PRECOMPILE_AUTO=0 \
        docker.io/library/julia:1.13 julia --startup-file=no --project=/work/proj /scripts/julia2.jl

Notable features (differences from julia-manifest-v2 first):

- `manifest_format = "2.1"`, `julia_version = "1.13.3"`. Pkg 1.13's manifest.jl
  (`manifest_format_for`) writes 2.1 for Julia >= 1.13 and 2.0 for older versions.
- Every registry package has `registries = "General"`, and the file ends with a
  `[registries.General]` table: `url = "https://github.com/JuliaRegistries/General.git"`,
  `uuid = "23338594-aafe-5451-b93e-139f81909106"`. Per Pkg's manifest.jl, `registries` is a string
  for one registry and an array for several. Stdlibs and the URL package have no `registries`.
- Project.toml has a `[sources]` table written by `Pkg.add(url=…, rev=…)`:
  `Example = {rev = "82d1224c32990c0105898fa44009864f5648e98d", url = "https://github.com/JuliaLang/Example.jl"}`.
- `project_hash` (`968f9a20…`) is again Pkg's SHA-1 over its own text of the project (deps, weak
  deps, compat and, from 1.13.1, `[sources]`: `workspace_resolve_hash` in Pkg's Types.jl). Not a
  file hash (`sha1sum Project.toml` differs).
- Resolution differs from 1.11: PrecompileTools 1.4.0 (`git-tree-sha1` `1e697ad6…`, equal to its
  General entry), stdlib SHA 1.0.0.
- Otherwise as julia-manifest-v2: 14 `[[deps.<Name>]]` entries; JSON 1.13.4 with
  `git-tree-sha1 = "06d90f699285d055e34f0b014636a75a17ff2252"` (= General's entry =
  `git rev-parse 'v1.13.4^{tree}'`); URL package Example 0.5.5 with `repo-url`, `repo-rev` and the
  commit's tree `84ec6704…`; stdlibs with `uuid` and `version` but no `git-tree-sha1`; weak
  dependencies named in `weakdeps`/`extensions` tables but not locked.
- LF line endings, trailing newline.
