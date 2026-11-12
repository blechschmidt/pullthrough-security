# pnpm-v5

Generated 2026-11-12 by real pnpm. pnpm-lock.yaml is unedited tool output. package.json was
written by hand first and pnpm did not change it.

- Tool: pnpm 7.33.7 (highest 7.x; the npm dist-tag latest-7 still points at 7.33.5), run through the host's npx on Node v22.23.2. It ran on Node 22, so no container was needed.
- Command:

      npx -y pnpm@7.33.7 install --lockfile-only --ignore-scripts

Notable features of pnpm-lock.yaml (`lockfileVersion: 5.4`, an unquoted YAML number):
- A top-level `specifiers` map (name → range from package.json), then `dependencies`/`optionalDependencies`/`devDependencies` maps of name → resolved version string. No `settings`, no `importers`.
- `packages` keys are `/name/version` with slash separators, e.g. `/@types/node/20.14.10`, `/string-width/4.2.3`.
- Alias: `dependencies: string-width-cjs: /string-width/4.2.3`.
- Git dependency is-number from GitHub: `is-number: github.com/jonschlinkert/is-number/98e8ff1da1a89f93d1397a24d7413ed15421c139`. The package entry has a tarball resolution (codeload URL), `name: is-number` and `version: 7.0.0`.
- Per-package `dev`, `optional` and `requiresBuild` (on ms) flags; `deprecated` on left-pad; `engines`.
