# yarn-classic

Generated 2026-11-12 by real Yarn 1. yarn.lock is unedited tool output. package.json was written
by hand first and Yarn did not change it.

- Tool: Yarn 1.22.22 via corepack 0.34.6 (`corepack yarn@1.22.22`), Node v22.23.2.
- Commands:

      corepack yarn@1.22.22 install --ignore-scripts --non-interactive --no-progress
      rm -rf node_modules   # stayed in scratch, never copied

- Environment: scratch dir and scratch HOME (`.yarnrc`: `ignore-scripts true`, `.npmrc`: `ignore-scripts=true`). Yarn reported "Ignored scripts due to flag."

Notable features of yarn.lock (header `# yarn lockfile v1`):
- Yarn's own format, not YAML: `key:` lines with 2-space-indented `version`, `resolved`, `integrity` and `dependencies`. Keys are quoted where needed, e.g. `"@types/node@20.14.10"`.
- Registry `resolved` URLs point at registry.yarnpkg.com and end in `#<sha1>`. Each also has a sha512 `integrity`.
- Alias string-width-cjs → string-width: key `"string-width-cjs@npm:string-width@^4.2.0"`, version 4.2.3, resolved string-width-4.2.3.tgz.
- Git dependency is-number from GitHub: key `"is-number@github:jonschlinkert/is-number#7.0.0"`, version 7.0.0, resolved `https://codeload.github.com/jonschlinkert/is-number/tar.gz/98e8ff1da1a89f93d1397a24d7413ed15421c139`, no integrity.
- No dev/optional information. left-pad and ms look like any other entry; only package.json says they are devDependencies/optionalDependencies.
- Range keys (`ansi-regex@^5.0.1`, `undici-types@~5.26.4`) and `dependencies` blocks with quoted ranges (`undici-types "~5.26.4"`).
- No entry for the root project.
