# npm-v3

Generated 2026-11-13 by real npm 10.9.8 (host, Node v22.23.2), lock only, scripts off
(`npm_config_ignore_scripts=true`, a scratch npm cache). Neither lock file was edited.

- before/package-lock.json (`"lockfileVersion": 3`): package.json first pinned `"ms": "2.1.2"`,
  `npm install --package-lock-only`; then package.json was changed to `"ms": "^2.1.2"` (as it is
  here) and `npm install --package-lock-only` run again, which kept ms 2.1.2 and recorded the range.
- after/package-lock.json: `npm update ms --package-lock-only` on that. npm moved
  `node_modules/ms` to 2.1.3 (`version`, `resolved`, `integrity`) and changed nothing else; package.json
  was left as it is.

Features: nested duplicates of ms 2.0.0 (`node_modules/debug/node_modules/ms`,
`node_modules/send/node_modules/ms`) next to the hoisted ms 2.1.2; scoped `@types/node`; the alias
`string-width-cjs` → `"name": "string-width"`; left-pad `dev: true`.

`npm shrinkwrap` in the before directory renamed package-lock.json to an npm-shrinkwrap.json
byte-identical to before/package-lock.json, and `npm update ms --package-lock-only` then rewrote
npm-shrinkwrap.json byte-identically to after/package-lock.json: the shrinkwrap tests use these files
under that name.
