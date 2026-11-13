# composer-git

Generated 2026-11-12 with Composer 2.11.2 (PHP 8.5.12) in podman, image `docker.io/library/composer:2`
= `docker.io/library/composer@sha256:ca11f643d7791ebdd90a34fc20caf11380d434007ae539a9ea75cd9212e13dca`.
`composer.json` is the hand-written input; `composer.lock` was not edited afterwards.

    podman run --rm -v <scratch>:/app -e COMPOSER_HOME=<scratch home> -w /app docker.io/library/composer:2 \
      composer update --no-install --no-interaction --no-plugins --no-scripts

- `composer.json` declares a repository of `"type": "git"` for https://github.com/php-fig/log.git, which
  makes Composer read that repository with its plain Git driver: Composer clones it and reads the
  tags, and the package it locks from there has a `source` (`type: git`, the URL, `reference`: the
  commit f16e1d5863e37f8d8c2a01719f5b34baa2b714d3 of tag 3.0.2) and no `dist` at all. It is installed
  from the repository — a Git dependency.
- psr/container 2.0.2 comes from Packagist: a `dist` zip from api.github.com with an empty `shasum`
  (Packagist leaves it empty for archives GitHub builds on demand) and the commit as `reference`.
- No `packages-dev`.
