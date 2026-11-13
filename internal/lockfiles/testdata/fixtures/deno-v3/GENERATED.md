# deno-v3

Generated 2026-11-12 by real Deno on the host (linux/amd64). deno.lock is unedited tool
output. deno.json and main.ts are byte-identical to deno-v5's; Deno did not change them and
created no node_modules directory.

- Tool: Deno 1.46.3 (release, x86_64-unknown-linux-gnu; v8 12.9.202.5-rusty, typescript
  5.5.2), the last 1.x release. `deno-x86_64-unknown-linux-gnu.zip` came from the GitHub
  release. That release publishes no checksum; the zip's sha256 was
  39bb1d21ad19c16fcb14f9d58fb542c2bccf0cd92c19aee8127ac5112b48bf83.
- Command: as for deno-v5, with a fresh scratch DENO_DIR:

      env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=<scratch>/home TMPDIR=<scratch>/tmp LANG=C.UTF-8 \
        DENO_DIR=<scratch>/deno-dir DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 \
        deno cache main.ts

  `deno cache --frozen main.ts` afterwards succeeded and left the file byte-identical.
- Inputs: see deno-v5. Deno 1.46 already resolves `jsr:` specifiers.

Notable features of deno.lock (9524 bytes, 209 lines, 2-space JSON, LF, trailing newline, no
paths):

- `"version": "3"`. Top-level keys, in order: `version`, `packages`, `redirects`, `remote`,
  `workspace`. `packages` holds `specifiers`, `jsr` and `npm`, which v4/v5 have at top level.
- `packages.specifiers` keeps the requirement exactly as written, and the value is fully
  qualified with scheme and name:
  - `"jsr:@std/assert@^1.0.0": "jsr:@std/assert@1.0.19"`;
  - `"jsr:@std/internal@^1.0.12": "jsr:@std/internal@1.0.14"`;
  - `"npm:chalk@5": "npm:chalk@5.6.2"`.
- `packages.jsr` has the same shape and values as in v4/v5: `<@scope/name>@<version>` →
  `{"integrity", "dependencies"}`.
  - `integrity` is the lowercase hex SHA-256 of `https://jsr.io/<@scope/name>/<version>_meta.json`
    (all three checked).
  - `dependencies` is a list of specifier strings, absent when empty.
- `packages.npm` maps `<name>@<version>` → `{"integrity", "dependencies"}`.
  - `integrity` is the registry's `dist.integrity`, an SRI SHA-512 of the tarball (all 32
    checked).
  - `dependencies` is always present. It is a map from dependency name to the locked package
    key, e.g. strip-ansi has `{"ansi-regex": "ansi-regex@6.6.0"}`, and it is `{}` when empty.
  - Optional dependencies are included: esbuild's map has all 26 `@esbuild/*` entries, each
    also locked.
  - There are no `os`/`cpu`/`bin`/`scripts`/`deprecated` fields.
- `redirects` and `remote` are as in v4/v5: the unversioned deno.land URL → the 0.224.0 URL,
  and `remote` holds the hex SHA-256 of the body of the 0.224.0 `colors.ts` (checked).
- `workspace.dependencies` lists the `jsr:`/`npm:` values of deno.json `imports` sorted and
  exactly as written (`jsr:@std/assert@^1.0.0`, `npm:chalk@5`, …). The `https:` import is not
  listed.
