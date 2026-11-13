# npm-workspaces-v2

Generated 2026-11-13 by real npm 8.19.4 (Node v22.23.2), lock only, scripts off. Unedited tool output.

Workspaces `packages/*`: packages/a depends on lodash and ms 2.0.0, packages/b on @fixture/a and
ms. The manifests first pinned `"lodash": "4.17.20"` and `"ms": "2.1.2"` exactly, `npm install
--package-lock-only` ran, then they were changed to `^4.17.20` and `^2.1.2` (as they are here) and
it ran again: before/package-lock.json. `npm update lodash ms --package-lock-only` then wrote
after/package-lock.json, moving lodash 4.17.20 → 4.18.1 and the ms 2.1.2 nested under the workspace
folder (`packages/b/node_modules/ms`) → 2.1.3; the hoisted ms 2.0.0 stayed. The manifests were
left as they are.

`"lockfileVersion": 2`: the legacy tree nests b's ms under the workspace link entry
`"@fixture/b": {"version": "file:packages/b", …, "dependencies": {"ms": …}}`.
