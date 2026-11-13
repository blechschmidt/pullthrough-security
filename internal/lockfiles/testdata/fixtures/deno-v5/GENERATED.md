# deno-v5

Generated 2026-11-12 by real Deno on the host (linux/amd64). deno.lock is unedited tool
output. deno.json and main.ts were written by hand first; Deno did not change them and
created no node_modules directory (there is no package.json, so packages went to DENO_DIR).

- Tool: Deno 2.9.8 (stable, x86_64-unknown-linux-gnu; v8 15.0.245.2-rusty, typescript 6.0.3).
  This is the latest 2.x release, from 2026-10-21. `deno-x86_64-unknown-linux-gnu.zip` came
  from the GitHub release; its sha256
  e890975bc2549807bbcc0b584ffafda72cc7c93349dd99c80483dd784f6c4609 equals the published
  `.zip.sha256sum`.
- Command: scratch HOME and DENO_DIR, no other environment:

      env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=<scratch>/home TMPDIR=<scratch>/tmp LANG=C.UTF-8 \
        DENO_DIR=<scratch>/deno-dir DENO_NO_UPDATE_CHECK=1 NO_COLOR=1 \
        deno cache main.ts

  Deno warned "Implicitly using latest version (0.224.0) for https://deno.land/std/fmt/colors.ts".
  `deno cache --frozen main.ts` afterwards succeeded and left the file byte-identical.
- Inputs. deno.json `imports`:
  - `jsr:@std/assert@^1.0.0` and `jsr:@std/path@^1.0.0`;
  - `npm:chalk@5`, `npm:strip-ansi@7`, `npm:ansi-regex@5`, `npm:esbuild@0.28` and
    `npm:left-pad@1`;
  - `colors` → `https://deno.land/std@0.224.0/fmt/colors.ts`.

  main.ts imports all of them, plus the unversioned `https://deno.land/std/fmt/colors.ts`.
  Several imports exist only to exercise lock fields:
  - strip-ansi@7 → ansi-regex@^6 gives an npm dependency edge, since chalk 5 has no
    dependencies.
  - ansi-regex@5 puts two versions of one name in the lock.
  - esbuild has a `bin`, a `postinstall` script and 26 optional platform packages with `os`/`cpu`.
  - left-pad 1.3.0 is deprecated.
  - The unversioned URL produces a redirect.

Notable features of deno.lock (8677 bytes, 232 lines, 2-space JSON, LF, trailing newline, no
paths):

- `"version": "5"`. Top-level keys, in order: `version`, `specifiers`, `jsr`, `npm`,
  `redirects`, `remote`, `workspace`.
- `specifiers` maps `<jsr|npm>:<name>@<requirement>` → the resolved version, as a bare
  version string.
  - deno.json's `^1.0.0` is written as `1`, e.g. `"jsr:@std/assert@1": "1.0.19"`.
  - Requirements taken from package metadata keep their form: `"jsr:@std/internal@^1.0.12"`
    and `"jsr:@std/internal@^1.0.14"` both map to `1.0.14`.
  - npm entries look like `"npm:chalk@5": "5.6.2"` and `"npm:esbuild@0.28": "0.28.2"`.
- `jsr` maps `<@scope/name>@<version>` → `{"integrity", "dependencies"}`.
  - `integrity` is the lowercase hex SHA-256 of the version manifest
    `https://jsr.io/<@scope/name>/<version>_meta.json`. Checked for all three: @std/assert
    1.0.19, @std/internal 1.0.14 and @std/path 1.1.6.
  - `dependencies` is a list of specifier strings (`"jsr:@std/internal@^1.0.12"`) to look up in
    `specifiers`. It is absent when empty (@std/internal).
- The `_meta.json` has `manifest`, `exports` and `moduleGraph2`. `manifest` maps each file
  path to `{size, checksum: "sha256-<hex>"}`; that checksum is hex, not base64. The `/mod.ts`
  checksum of @std/path 1.1.6 equals the SHA-256 of https://jsr.io/@std/path/1.1.6/mod.ts.
  JSR module files never appear in `remote`; they are pinned only through this manifest.
- `npm` maps `<name>@<version>` → object. Scoped names keep their leading `@`, e.g.
  `@esbuild/linux-x64@0.28.2`. Fields are omitted when empty or false, so chalk 5.6.2 is just
  `{"integrity": ...}`. The fields are:
  - `integrity`: the registry's `dist.integrity`, an SRI SHA-512 of the tarball. All 32 were
    checked against registry.npmjs.org, and chalk-5.6.2.tgz was also hashed.
  - `dependencies`: a list. Entries are bare names when the lock has one version of that name,
    and `<name>@<version>` when it has several. strip-ansi has `["ansi-regex@6.6.0"]` because
    ansi-regex 5.0.1 is also locked.
  - `optionalDependencies`: a separate list. esbuild has the 26 `@esbuild/*` names.
  - `os` and `cpu`: copied from the package metadata, present on every `@esbuild/*` package,
    e.g. `"os": ["linux"], "cpu": ["x64"]`.
  - `bin: true` and `scripts: true` on esbuild, which has a `bin` and a `postinstall` script.
  - `deprecated: true` on left-pad 1.3.0. The deprecation message itself is not stored.
- No npm entry stores a tarball URL.
- All 26 `@esbuild/*` packages are locked, although only `@esbuild/linux-x64` was downloaded and
  unpacked into DENO_DIR.
- `redirects` is
  `{"https://deno.land/std/fmt/colors.ts": "https://deno.land/std@0.224.0/fmt/colors.ts"}`;
  deno.land answers that URL with HTTP 302.
- `remote` maps the URL `https://deno.land/std@0.224.0/fmt/colors.ts` → `508563c0…e1c5`, the
  lowercase hex SHA-256 of the response body (checked). Only the redirect target is hashed.
- `workspace.dependencies` is the sorted list of the `jsr:`/`npm:` values of deno.json
  `imports`, with the same normalised requirements as `specifiers` (`jsr:@std/assert@1`). The
  `https:` import (`colors`) and transitive packages are not listed.
- With the same deno.json and main.ts, Deno 2.0.6 writes deno-v4: only `version` and the `npm`
  entries differ. A first trial that had only chalk, strip-ansi and ansi-regex as npm
  packages gave v4 and v5 files that differed only in the version line.
