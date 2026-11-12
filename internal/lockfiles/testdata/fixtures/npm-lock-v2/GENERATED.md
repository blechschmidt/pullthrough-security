# npm-lock-v2

Generated 2026-11-12 by real npm. package-lock.json is unedited tool output. package.json was
written by hand first and npm did not change it.

- Tool: npm 8.19.4 (latest 8.x), run through the host's npx on Node v22.23.2. It worked on Node 22, so no node:16 container was needed.
- Command:

      npx -y npm@8.19.4 install --package-lock-only --ignore-scripts --no-audit --no-fund

- Environment: as for npm-lock-v3 (scratch dir, scratch HOME with `ignore-scripts=true`).

Notable features of package-lock.json (`"lockfileVersion": 2`, `"requires": true`):
- Both sections: the v3-style `packages` map (12 entries incl. root `""`) AND the legacy v1-style `dependencies` tree (11 entries) for the same packages.
- `packages` has the same shape as in npm-lock-v3, but npm 8 records `license` only on the git dependency is-number.
- Alias string-width-cjs → string-width: `packages["node_modules/string-width-cjs"]` has `"name": "string-width"`, version 4.2.3; legacy `dependencies["string-width-cjs"].version` is `"npm:string-width@4.2.3"`.
- Git dependency is-number from GitHub: in `packages`, `"resolved": "git+ssh://git@github.com/jonschlinkert/is-number.git#98e8ff1da1a89f93d1397a24d7413ed15421c139"`, version 7.0.0. In the legacy tree, `"version"` is that git+ssh URL and `"from": "is-number@github:jonschlinkert/is-number#7.0.0"`, with no `resolved`/`integrity`.
- Legacy entries list edges as `requires` (name → range); `packages` entries use `dependencies`.
- left-pad: `dev: true` in both sections, `deprecated` only in `packages`. ms: `optional: true` in both.
- Scoped @types/node → undici-types 5.26.5 (range ~5.26.4). Flat tree, no nested entries.
