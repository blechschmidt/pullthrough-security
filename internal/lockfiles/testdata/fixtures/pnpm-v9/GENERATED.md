# pnpm-v9

Generated 2026-11-12 by real pnpm. pnpm-lock.yaml is unedited tool output. package.json was
written by hand first and pnpm did not change it.

- Tool: pnpm 9.15.9 (latest 9.x), run through the host's npx on Node v22.23.2.
- Command (lock only, no node_modules):

      npx -y pnpm@9.15.9 install --lockfile-only --ignore-scripts

- pnpm warned "The git-hosted package fetched from https://codeload.github.com/... has to be built but the build scripts were ignored". Nothing was run (is-number 7.0.0 only has a `test` script).

Notable features of pnpm-lock.yaml (`lockfileVersion: '9.0'`):
- `settings` (autoInstallPeers, excludeLinksFromLockfile), then `importers` → `.` with `dependencies`/`optionalDependencies`/`devDependencies`, each dep `{specifier, version}`.
- Separate `packages` (metadata: `resolution: {integrity}`, `engines`, `deprecated`) and `snapshots` (dependency edges, `optional: true`) sections. Keys are `name@version` with no leading slash; the scoped key is quoted: `'@types/node@20.14.10'`.
- Alias string-width-cjs → string-width: importer `version: string-width@4.2.3`; the package is keyed `string-width@4.2.3`, so the alias name appears only in the importer.
- Git dependency is-number from GitHub: importer `version: https://codeload.github.com/jonschlinkert/is-number/tar.gz/98e8ff1da1a89f93d1397a24d7413ed15421c139`. The package key is `is-number@<that URL>`, with `resolution: {tarball: <that URL>}` (no integrity) and an explicit `version: 7.0.0`.
- Dev status shows only in `importers.devDependencies` (left-pad); there are no `dev:` flags. ms has `optional: true` in `snapshots`.
- left-pad: `deprecated: use String.prototype.padStart()`.
