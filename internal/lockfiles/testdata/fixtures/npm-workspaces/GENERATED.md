# npm-workspaces

Generated 2026-11-12 by real npm. package-lock.json is unedited tool output. The three
package.json files were written by hand first and npm did not change them.

- Tool: npm 10.9.8 (host), Node v22.23.2.
- Command, at the workspace root:

      npm install --package-lock-only --ignore-scripts --no-audit --no-fund

- Layout: root package.json (`private`, `"workspaces": ["packages/*"]`, devDependency left-pad 1.3.0); packages/a/package.json (`@fixture/a` 1.0.0, depends on lodash 4.17.21); packages/b/package.json (`@fixture/b` 1.0.0, depends on `@fixture/a` 1.0.0 and ms 2.1.3). Both workspace packages have `"version": "1.0.0"`, so b's `"@fixture/a": "1.0.0"` is satisfied by the workspace.

Notable features of package-lock.json (`"lockfileVersion": 3`):
- The root `""` entry lists `"workspaces": ["packages/*"]` and the devDependencies.
- Workspace links: `node_modules/@fixture/a` is `{"resolved": "packages/a", "link": true}` and `node_modules/@fixture/b` is `{"resolved": "packages/b", "link": true}`, with no version and no integrity.
- Workspace package entries are keyed by path, not under node_modules: `packages/a` and `packages/b` (name, version, dependencies).
- `@fixture/a` is never fetched from a registry; b's dependency on it resolves to the link.
- Registry packages lodash, ms and left-pad are hoisted to the root `node_modules/`. left-pad has `dev: true` + `deprecated`. ms is a normal (not optional) dependency here.
