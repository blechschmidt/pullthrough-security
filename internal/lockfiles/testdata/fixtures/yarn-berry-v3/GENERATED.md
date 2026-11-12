# yarn-berry-v3

Generated 2026-11-12 by real Yarn 3. yarn.lock is unedited tool output. package.json was written
by hand first and Yarn did not change it.

- Tool: Yarn 3.8.7 (latest 3.x) via corepack 0.34.6 (`corepack yarn@3.8.7`), Node v22.23.2.
- Project `.yarnrc.yml` in scratch (not copied): `nodeLinker: node-modules`, `enableScripts: false`.
- Command:

      corepack yarn@3.8.7 install --mode=update-lockfile

Notable features of yarn.lock (`__metadata: version: 6, cacheKey: 8`):
- Same layout as Yarn 4: descriptor keys with the `npm:` protocol, `resolution`, `languageName`, `linkType`, and a root `"fixture-app@workspace:."` entry (`0.0.0-use.local`, `linkType: soft`, `dependenciesMeta: ms: optional: true`).
- Differences from version 8: dependency ranges have no `npm:` prefix (`undici-types: ~5.26.4`; workspace `"@types/node": 20.14.10`), and `checksum` is bare sha512 hex without a `<cacheKey>/` prefix. The checksum hashes Yarn's cache archive, so it differs from both the npm integrity and the Yarn 4 checksum of the same package.
- Alias: key `"string-width-cjs@npm:string-width@^4.2.0"` → `resolution: "string-width@npm:4.2.3"`.
- Git dependency is-number from GitHub: key `"is-number@github:jonschlinkert/is-number#7.0.0"` → `resolution: "is-number@https://github.com/jonschlinkert/is-number.git#commit=98e8ff1da1a89f93d1397a24d7413ed15421c139"`.
- left-pad (dev) is listed in the workspace's `dependencies` with no dev flag. Yarn reported YN0061 "left-pad@npm:1.3.0 is deprecated", but the lock file does not record it.
