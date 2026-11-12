# pnpm-v6

Generated 2026-11-12 by real pnpm. pnpm-lock.yaml is unedited tool output. package.json was
written by hand first and pnpm did not change it.

- Tool: pnpm 8.15.9 (latest 8.x), run through the host's npx on Node v22.23.2.
- Command:

      npx -y pnpm@8.15.9 install --lockfile-only --ignore-scripts

Notable features of pnpm-lock.yaml (`lockfileVersion: '6.0'`):
- `settings` block, then a single-project layout: top-level `dependencies`, `optionalDependencies` and `devDependencies` with `{specifier, version}` (no `importers` key).
- `packages` keys are `/name@version` with a leading slash, e.g. `/@types/node@20.14.10`. Dependency edges sit inside each package (`dependencies: {undici-types: 5.26.5}`). There is no `snapshots` section.
- Per-package flags: `dev: true|false`, `optional: true`, and `requiresBuild: true` on ms (ms has no install scripts; the flag is still there).
- Alias: `string-width-cjs: {specifier: npm:string-width@^4.2.0, version: /string-width@4.2.3}` → package `/string-width@4.2.3`.
- Git dependency is-number from GitHub: `version: github.com/jonschlinkert/is-number/98e8ff1da1a89f93d1397a24d7413ed15421c139`. The package key is that same string (no leading slash), with `resolution: {tarball: https://codeload.github.com/jonschlinkert/is-number/tar.gz/98e8ff1…}`, `name: is-number` and `version: 7.0.0`.
- left-pad: `deprecated` and `dev: true`.
