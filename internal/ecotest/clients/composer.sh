#!/bin/sh
# composer — replace Packagist with the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(composer --version --no-ansi | awk '{print $3}')"
export COMPOSER_HOME="$PWD/composer-home" COMPOSER_CACHE_DIR="$PWD/composer-cache"
export COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1

# Switch packagist.org off and add the proxy, in the global config: the proxy is
# then the only repository of every project, without touching any composer.json.
# Adding the proxy is not enough (nor is redefining "packagist"): Composer asks
# an added repository first and keeps asking packagist.org too. The proxy
# rewrites the metadata it serves, so package metadata and dist archives (hosted
# on GitHub) come back through it.
composer config --global repositories.packagist.org false
composer config --global repositories.pullthrough composer "$MOUNT"
# Only needed because the test proxy speaks plain HTTP.
composer config --global secure-http false

mkdir app
cd app
composer init --no-interaction --name ecotest/app >/dev/null
composer require --prefer-dist --no-progress "$PKG_NAME:$PKG_VERSION"
test -d "vendor/$PKG_NAME"

# Composer going to packagist.org behind the proxy's back is invisible in an
# install on a network without a way out: it shrugs and carries on. The audit
# does not — it exits 100 when a repository it asks cannot be reached — so it
# passes only when the proxy is the only repository. (1 would mean an advisory
# was found for the package.)
composer audit || [ "$?" -lt 100 ]
