# npm-shrinkwrap

Generated 2026-11-12 by real npm. npm-shrinkwrap.json is unedited tool output; there is no
package-lock.json in this directory. package.json was written by hand first and npm did not change it.

- Tool: npm 10.9.8 (host), Node v22.23.2.
- Commands:

      npm install --package-lock-only --ignore-scripts --no-audit --no-fund
      npm shrinkwrap --ignore-scripts
      # npm notice package-lock.json has been renamed to npm-shrinkwrap.json

- Environment: as for npm-lock-v3.

Notable features of npm-shrinkwrap.json (`"lockfileVersion": 3`):
- Only the file name is special. The content is byte-identical to npm-lock-v3/package-lock.json (same input, same npm).
- Same features as that file: alias string-width-cjs → string-width (`"name": "string-width"`), git dependency is-number as `git+ssh://git@github.com/jonschlinkert/is-number.git#98e8ff1da1a89f93d1397a24d7413ed15421c139`, left-pad `dev: true` + `deprecated`, ms `optional: true`, scoped @types/node → undici-types.
