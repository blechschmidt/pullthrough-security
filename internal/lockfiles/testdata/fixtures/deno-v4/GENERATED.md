# deno-v4

Generated 2026-11-12 by real Deno on the host (linux/amd64). deno.lock is unedited tool
output. deno.json and main.ts are byte-identical to deno-v5's; Deno did not change them and
created no node_modules directory.

- Tool: Deno 2.0.6 (stable, x86_64-unknown-linux-gnu; v8 12.9.202.13-rusty, typescript
  5.6.2), the last 2.0.x release, from 2024-11-10. `deno-x86_64-unknown-linux-gnu.zip` came
  from the GitHub release; its sha256
  946c370617bfc041a353a5fb19b84c209461b1c2bb902908702e699a5276659e equals the published
  `.zip.sha256sum`.
- Command: as for deno-v5, with a fresh scratch DENO_DIR:

      env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=<scratch>/home TMPDIR=<scratch>/tmp LANG=C.UTF-8 \
        DENO_DIR=<scratch>/deno-dir DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 \
        deno cache main.ts

  `deno cache --frozen main.ts` afterwards succeeded and left the file byte-identical.
- Inputs: see deno-v5 for what each import is for. They are JSR @std/assert and @std/path
  (`^1.0.0`), npm chalk@5, strip-ansi@7, ansi-regex@5, esbuild@0.28 and left-pad@1, the
  pinned `https://deno.land/std@0.224.0/fmt/colors.ts`, and the unversioned
  `https://deno.land/std/fmt/colors.ts`.

Notable features of deno.lock (7372 bytes, 177 lines, 2-space JSON, LF, trailing newline, no
paths):

- `"version": "4"`. The top-level keys and their order are the same as v5: `version`,
  `specifiers`, `jsr`, `npm`, `redirects`, `remote`, `workspace`.
- Everything except `version` and the `npm` entries is identical to deno-v5 (compared with
  jq):
  - `specifiers` (`"jsr:@std/assert@1": "1.0.19"`, `"npm:chalk@5": "5.6.2"`; deno.json's
    `^1.0.0` is written as `1`);
  - `jsr` (`integrity` = hex SHA-256 of `https://jsr.io/<@scope/name>/<version>_meta.json`,
    `dependencies` = list of specifiers);
  - `redirects`, `remote` (hex SHA-256 of the response body) and `workspace.dependencies`.
- `npm` entries have only `integrity` and, when non-empty, `dependencies`:
  - `integrity` is the registry's `dist.integrity`, an SRI SHA-512 of the tarball.
  - Optional dependencies are merged into `dependencies`: esbuild 0.28.2's `dependencies`
    lists the 26 `@esbuild/*` platform packages.
  - There are no `optionalDependencies`, `os`, `cpu`, `bin`, `scripts` or `deprecated` fields.
    Nothing in the lock says that the `@esbuild/*` packages are platform-specific, that
    esbuild has an install script, or that left-pad is deprecated.
  - As in v5, a dependency entry is a bare name when unambiguous and `<name>@<version>`
    otherwise. strip-ansi has `["ansi-regex@6.6.0"]` because ansi-regex 5.0.1 is also locked.
- All 26 `@esbuild/*` packages are locked (integrity only), although only `@esbuild/linux-x64`
  was downloaded.
- All hashes were checked as in deno-v5: 3 JSR manifests, 32 npm `dist.integrity` values and
  1 remote module.
