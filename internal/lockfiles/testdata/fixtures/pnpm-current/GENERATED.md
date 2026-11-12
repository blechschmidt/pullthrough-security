# pnpm-current

Generated 2026-11-12 by real pnpm. pnpm-lock.yaml is unedited tool output. package.json was
written by hand first and pnpm did not change it.

- Tool: pnpm 12.3.4, the version the host's corepack provides as `pnpm`. It was run as `corepack pnpm@12.3.4` (corepack 0.34.6, Node v22.23.2) so that the scratch corepack home could not pick a different version.
- Command:

      corepack pnpm@12.3.4 install --lockfile-only --ignore-scripts

Notable features of pnpm-lock.yaml (`lockfileVersion: '9.0'`; pnpm 12 still writes the 9.0 format):
- Same structure as pnpm-v9: `settings`, `importers`, `packages`, `snapshots`, `name@version` keys.
- Differences from pnpm-v9 (pnpm 9.15.9): the importer lists `devDependencies` before `optionalDependencies`, and the git-hosted package's resolution is `{gitHosted: true, integrity: sha512-i6H8…, tarball: https://codeload.github.com/jonschlinkert/is-number/tar.gz/98e8ff1…}`, where pnpm 9 wrote only `tarball`.
- Alias string-width-cjs → `string-width@4.2.3`, scoped @types/node → undici-types, ms `optional: true` in `snapshots`, deprecated left-pad: as in pnpm-v9.
