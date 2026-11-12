# yarn-berry-v4

Generated 2026-11-12 by real Yarn 4. yarn.lock is unedited tool output. package.json was written
by hand first and Yarn did not change it (no `packageManager` field was added).

- Tool: Yarn 4.13.0 via corepack 0.34.6 (`corepack yarn@4.13.0`), Node v22.23.2.
- Project `.yarnrc.yml` in scratch (not copied): `nodeLinker: node-modules`, `enableScripts: false`.
- Command (lock only: resolution, plus fetching to compute checksums; link step skipped):

      corepack yarn@4.13.0 install --mode=update-lockfile

- Deviation: the newest Yarn 4.x (4.18.1) does not write `__metadata.version 8`. Checked in each release bundle (`YARN_LOCKFILE_VERSION_OVERRIDE ?? N`): 4.9.4–4.13.0 write 8, 4.14.0/4.14.1 write 9, 4.15.0–4.18.1 write 10. Yarn 4.14+ also refuses git dependencies until `approvedGitRepositories` allows them (YN0080). 4.13.0 is the newest release that writes version 8, so it was used. A 4.18.1 lock of the same project (with the repo approved) differs from this file only in the line `version: 10`.

Notable features of yarn.lock (`__metadata: version: 8, cacheKey: 10c0`):
- YAML. Keys are descriptors with a protocol: `"@types/node@npm:20.14.10"`, `"ansi-regex@npm:^5.0.1"`. Dependency ranges carry `npm:` too (`undici-types: "npm:~5.26.4"`).
- `resolution` is the locator (`"@types/node@npm:20.14.10"`). `checksum: 10c0/<sha512 hex>` hashes Yarn's own cache archive and is prefixed with the cacheKey. It is NOT the registry tarball's sha512 (lodash: npm integrity starts bf690311…, this checksum d8cbea07…). `languageName: node`, `linkType: hard`.
- Root workspace entry `"fixture-app@workspace:."`: `version: 0.0.0-use.local`, `languageName: unknown`, `linkType: soft`. Its `dependencies` merge dependencies, devDependencies and optionalDependencies, plus `dependenciesMeta: ms: optional: true`. There is no dev flag anywhere.
- Alias string-width-cjs → string-width: key `"string-width-cjs@npm:string-width@^4.2.0"`, `resolution: "string-width@npm:4.2.3"`.
- Git dependency is-number from GitHub: key `"is-number@github:jonschlinkert/is-number#7.0.0"`, `resolution: "is-number@https://github.com/jonschlinkert/is-number.git#commit=98e8ff1da1a89f93d1397a24d7413ed15421c139"`, version 7.0.0, with a checksum of the package Yarn packed from the git source.
- Scoped @types/node → undici-types 5.26.5.
