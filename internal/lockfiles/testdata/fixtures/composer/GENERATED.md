# composer fixture — how it was generated

`composer.lock` was written by real Composer (2026-11-12, linux/amd64); it is not hand-made and must not be edited.

- Tool: Composer 2.11.2 (2026-11-10 10:09:37), PHP 8.5.12
- Image: `composer:2` = `composer@sha256:ca11f643d7791ebdd90a34fc20caf11380d434007ae539a9ea75cd9212e13dca`
- Input: `composer.json`

Command (lock only: no `vendor/`, no scripts, no plugins, no audit):

    docker run --rm -v /mnt/HC_Volume_106716549/pt178/jvm:/work -w /work/composer \
      -e COMPOSER_HOME=/tmp/composer-home -e COMPOSER_CACHE_DIR=/tmp/composer-cache composer:2 \
      sh -c 'composer --version && composer update --no-install --no-scripts --no-plugins --no-audit --no-interaction --no-progress'

Notable features of `composer.lock`:

- `packages`: monolog/monolog 3.7.0 and psr/log 3.0.2 (transitive, through monolog's `"psr/log": "^2.0 || ^3.0"`); `packages-dev`: psr/container 2.0.2.
- Entries do not say which packages are direct; only composer.json's `require`/`require-dev` do.
- Every package has `source` (git URL + commit `reference`) and `dist` (GitHub zipball URL + same `reference`).
- `dist.shasum` is `""` for all three packages, so the lock file carries no content digest.
- monolog has `"provide": {"psr/log-implementation": "3.0.0"}`, a virtual package that is not a locked package.
- Per-package `require` contains the platform requirement `php`, and monolog's `require-dev`/`suggest` contain `ext-*` names; neither is a package to fetch.
- Top level: `"platform": {}`, `"platform-dev": {}` (root has no php/ext requirement), `"aliases": []`, `"stability-flags": {}`, `"plugin-api-version": "2.11.0"`.
- No `version_normalized` in entries; each entry has both `time` and `published-time`.
- `content-hash` `1a5f44d27d75d83bd5cb81a61e544cfa` is derived from composer.json, so editing composer.json makes the lock "out of date".
- 4-space indent, LF, trailing newline.
