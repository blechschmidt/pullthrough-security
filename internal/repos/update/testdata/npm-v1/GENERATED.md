# npm-v1

Generated 2026-11-13 by real npm 6.14.18 (`npx -y npm@6.14.18`, Node v22.23.2), lock only, scripts off.
Unedited tool output.

- before/package-lock.json (`"lockfileVersion": 1`): exact pin `"ms": "2.1.2"`, `npm install
  --package-lock-only`, then the range `^2.1.2` and `npm install --package-lock-only` again.
- after/package-lock.json: the same two steps starting from `"ms": "2.1.3"`. (`npm update ms` in npm 6
  dropped the alias entries from the tree, an npm 6 quirk, so the file was generated afresh.) It
  differs from before/package-lock.json in the ms entry's version, resolved and integrity only.

Only the nested `dependencies` tree: ms 2.0.0 nested under debug and send, the alias
`"version": "npm:string-width@4.2.3"`, left-pad `dev: true`.
