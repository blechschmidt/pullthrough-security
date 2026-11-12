# npm-lock-v3

Generated 2026-11-12 by real npm. package-lock.json is unedited tool output. package.json was
written by hand first and npm did not change it (sha256 compared before and after).

- Tool: npm 10.9.8 (host), Node v22.23.2, Linux x86_64, no container.
- Command (lock only: no node_modules, no scripts):

      npm install --package-lock-only --ignore-scripts --no-audit --no-fund

- Environment: scratch project dir outside the repository; HOME/TMPDIR pointed at scratch dirs
  whose `.npmrc` sets `ignore-scripts=true`. This does not affect the lock file.

Notable features of package-lock.json (`"lockfileVersion": 3`, `"requires": true`):
- Only the `packages` map (no legacy `dependencies` tree). The root project is key `""` with name, version and the dependencies/devDependencies/optionalDependencies of package.json. 12 entries: root + 11 packages.
- Scoped package `node_modules/@types/node` 20.14.10 with `"dependencies": {"undici-types": "~5.26.4"}` → `node_modules/undici-types` 5.26.5.
- Alias string-width-cjs → string-width: key `node_modules/string-width-cjs` has `"name": "string-width"`, `"version": "4.2.3"` and the string-width-4.2.3.tgz tarball.
- Git dependency is-number from GitHub: `"resolved": "git+ssh://git@github.com/jonschlinkert/is-number.git#98e8ff1da1a89f93d1397a24d7413ed15421c139"` (tag 7.0.0 is that commit), `"version": "7.0.0"`, no `integrity`.
- left-pad 1.3.0: `"dev": true` and `"deprecated": "use String.prototype.padStart()"`.
- ms 2.1.3: `"optional": true`.
- Registry entries have `resolved` (registry.npmjs.org) and a sha512 `integrity`; every entry has `license`; some have `engines`.
- Flat tree: string-width's dependencies (emoji-regex, is-fullwidth-code-point, strip-ansi → ansi-regex) are hoisted; there are no nested `node_modules/x/node_modules/y` keys.
