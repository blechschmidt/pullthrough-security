# deno-v2

Generated 2026-11-12 by real Deno on the host (linux/amd64). deno.lock is unedited tool
output. deno.json and main.ts were written by hand first; Deno did not change them and
created no node_modules directory.

- Tool: Deno 1.33.4 (release, x86_64-unknown-linux-gnu; v8 11.4.183.2, typescript 5.0.4), the
  last 1.33.x release. `deno-x86_64-unknown-linux-gnu.zip` came from the GitHub release. That
  release publishes no checksum; the zip's sha256 was
  2e62448732a8481cae7af6637ddd37289e5baa6f22cd8e2f8197e25991869257.
- Command: as for deno-v5, with a fresh scratch DENO_DIR:

      env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=<scratch>/home TMPDIR=<scratch>/tmp LANG=C.UTF-8 \
        DENO_DIR=<scratch>/deno-dir DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 \
        deno cache main.ts

  A second `deno cache main.ts` left the file byte-identical.
- Inputs: the deno-v5 inputs without JSR, because Deno 1.33 predates JSR. The two `@std/*`
  imports and the `assertEquals(join(...))` line were dropped. The npm imports (chalk@5,
  strip-ansi@7, ansi-regex@5, esbuild@0.28, left-pad@1), the pinned
  `https://deno.land/std@0.224.0/fmt/colors.ts` import-map entry and the unversioned
  `https://deno.land/std/fmt/colors.ts` import are the same.

Notable features of deno.lock (1564 bytes, 43 lines, 2-space JSON, LF, trailing newline, no
paths):

- `"version": "2"`. Top-level keys, in order: `version`, `remote`, `npm`. There are no `jsr`,
  `redirects` or `workspace` sections.
- `remote` maps URL → lowercase hex SHA-256 of the response body. It has only
  `https://deno.land/std@0.224.0/fmt/colors.ts` → `508563c0…e1c5` (checked). The unversioned
  URL, which deno.land redirects to that one, appears nowhere in the file.
- `npm.specifiers` maps `<name>@<requirement>` → `<name>@<version>`, with no `npm:` prefix on
  either side, e.g. `"chalk@5": "chalk@5.6.2"` and `"esbuild@0.28": "esbuild@0.28.2"`.
- `npm.packages` maps `<name>@<version>` → `{"integrity", "dependencies"}`.
  - `integrity` is the registry's `dist.integrity`, an SRI SHA-512 of the tarball (all 6
    checked).
  - `dependencies` is always present, as a map from name to package key, e.g.
    `{"ansi-regex": "ansi-regex@6.6.0"}` on strip-ansi 7.2.0.
- esbuild's 26 optional dependencies are ignored entirely. Its entry is
  `"dependencies": {}`, no `@esbuild/*` package is locked (6 npm packages here, 32 in
  deno-v3 to v5), and Deno 1.33 did not download one.
