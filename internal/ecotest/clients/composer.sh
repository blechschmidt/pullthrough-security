#!/bin/sh
# composer — replace Packagist with the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(composer --version --no-ansi | awk '{print $3}')"
export COMPOSER_HOME="$PWD/composer-home" COMPOSER_CACHE_DIR="$PWD/composer-cache"
export COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1

# Redefining the "packagist" repository in the global config replaces
# repo.packagist.org for every project, without touching any composer.json. The
# proxy rewrites the metadata it serves, so package metadata and dist archives
# (hosted on GitHub) come back through it.
composer config --global repos.packagist composer "$MOUNT"
# Only needed because the test proxy speaks plain HTTP.
composer config --global secure-http false

mkdir app
cd app
composer init --no-interaction --name ecotest/app >/dev/null
composer require --prefer-dist --no-progress "$PKG_NAME:$PKG_VERSION"
test -d "vendor/$PKG_NAME"
