# npm-v2

Generated 2026-11-13 by real npm 8.19.4 (`npx -y npm@8.19.4`, Node v22.23.2), lock only, scripts off,
in the same two steps as npm-v3 (exact pin `"ms": "2.1.2"`, then the range `^2.1.2`), then
`npx -y npm@8.19.4 update ms --package-lock-only` for after/package-lock.json. Unedited tool output.

`"lockfileVersion": 2`: both the `packages` map and the legacy `dependencies` tree. npm moved ms
2.1.2 → 2.1.3 in both sections (version, resolved, integrity) and changed nothing else. The legacy
tree nests ms 2.0.0 under debug and under send, and spells the alias `"version": "npm:string-width@4.2.3"`.
