# npm-lock-v1

Generated 2026-11-12 by real npm 6 in a container. package-lock.json is unedited tool output.
package.json was written by hand first and npm did not change it.

- Tool: npm 6.14.18 on Node v14.21.3 (git 2.20.1), image `node:14` = `node@sha256:a158d3b9b4e3fa813fa6c8c590b8f0a860e015ad4e59bbce5744d2f6fd8461aa`.
- Command:

      docker run --rm -v /mnt/HC_Volume_106716549/pt178/js/work/npm-lock-v1:/work -w /work \
        -e npm_config_ignore_scripts=true -e npm_config_update_notifier=false node:14 \
        sh -c 'npm install --package-lock-only --ignore-scripts --no-audit --no-fund'

- The run took about 405 s. For the `github:` shorthand, npm 6 first tries `git://github.com/...` (GitHub turned that protocol off in 2022), retries, and then falls back to https. The output does not depend on this.

Notable features of package-lock.json (`"lockfileVersion": 1`, `"requires": true`):
- Only the legacy `dependencies` tree: no `packages` map and no root entry (name/version are top-level keys).
- The tree is flat. The dependency set has no version conflicts, so no entry has its own nested `dependencies` object.
- Edges are `requires` maps (name → range): @types/node → undici-types ~5.26.4; string-width-cjs → emoji-regex, is-fullwidth-code-point, strip-ansi; strip-ansi → ansi-regex.
- Alias string-width-cjs → string-width: `"version": "npm:string-width@4.2.3"`, resolved string-width-4.2.3.tgz, sha512 integrity.
- Git dependency is-number from GitHub, in npm 6 form: `"version": "github:jonschlinkert/is-number#98e8ff1da1a89f93d1397a24d7413ed15421c139"`, `"from": "github:jonschlinkert/is-number#7.0.0"`, with no `resolved` and no `integrity`. npm 7+ writes a `git+ssh://` URL instead.
- left-pad: `"dev": true` (v1 has no `deprecated` field). ms: `"optional": true`.
- No `license` or `engines` fields.
