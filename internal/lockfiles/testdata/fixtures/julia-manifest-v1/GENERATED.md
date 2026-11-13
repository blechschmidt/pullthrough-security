# julia-manifest-v1

Generated 2026-11-12 by real Pkg in a throwaway container. Project.toml and Manifest.toml are both
written by Pkg (the project started empty) and were not edited.

- Tool: Julia 1.6.7 (its bundled Pkg). 1.6 is the newest Julia that writes the old format:
  Julia 1.7.3 (`julia@sha256:dcc43f36078d69b02db3f1ca8584b615e0e84c7fdfe2ca5c65f70b4d89d98786`)
  already writes `manifest_format = "2.0"` with `[[deps.<Name>]]` (checked with a one-package
  probe; it writes `julia_version` but no `project_hash`).
- Image: `docker.io/library/julia:1.6` = `julia@sha256:8af048eda7c0aaec16364f69af3f6ee2bac17d3ea3d80c4f7e7423e5616d8c15`
- Same command and script as julia-manifest-v2, with `julia:1.6`:

      podman run --rm -v <scratch>:/work -v <scratch>/depot:/depot -v <scripts>:/scripts:ro -w /work/proj \
        -e JULIA_DEPOT_PATH=/depot -e JULIA_PKG_PRECOMPILE_AUTO=0 \
        docker.io/library/julia:1.6 julia --startup-file=no --project=/work/proj /scripts/julia2.jl

  Julia 1.6 still talks to today's Pkg server and General registry.

Notable features of Manifest.toml:

- Only the `#` header line, then one top-level `[[<Name>]]` array-of-tables entry per package (14),
  sorted by name. No `julia_version`, no `manifest_format`, no `project_hash`, no `deps.` prefix.
- Registry packages: JSON 0.21.4 (`deps = ["Dates", "Mmap", "Parsers", "Unicode"]`), Parsers 2.8.11,
  PrecompileTools 1.2.1, Preferences 1.6.1, each with `uuid`, `version` and `git-tree-sha1` (the
  git tree object id of the package source). Checked against General's Versions.toml: JSON 0.21.4
  `31e996f0…`, Parsers 2.8.11 `2facd7b5…`, PrecompileTools 1.2.1 `5aa36f70…` all equal.
- URL-tracked package Example 0.5.5: `repo-url`, `repo-rev = "82d1224c32990c0105898fa44009864f5648e98d"`,
  `git-tree-sha1 = "84ec67045e0af90908e775e4d7a3782b9f27e98a"` (the commit's tree, checked with
  git; the registered 0.5.5 tree is `e1f0e1a8…`).
- Stdlibs (Dates, Mmap, Printf, Random, SHA, Serialization, TOML, UUIDs, Unicode) have only `uuid`
  (and `deps`): no `version`, no `git-tree-sha1`. In format 2.0 written by Julia 1.11 they have a
  `version`.
- No `weakdeps`/`extensions` tables.
- Project.toml: `[deps]` with Dates, Example, JSON.
- LF line endings, trailing newline.
