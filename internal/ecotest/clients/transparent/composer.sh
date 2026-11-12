#!/bin/sh
# composer — install from Packagist, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(composer --version --no-ansi | awk '{print $3}')"
export COMPOSER_HOME="$PWD/composer-home" COMPOSER_CACHE_DIR="$PWD/composer-cache"
export COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1

# Composer keeps repo.packagist.org. It trusts the proxy's CA through its cafile
# setting; through a forward proxy it reads HTTPS_PROXY. The proxy moves the
# dist URLs (archives hosted on GitHub) onto repo.packagist.org, so the
# downloads are intercepted too.
composer config --global cafile "$PT_CA_CERT"

mkdir app
cd app
composer init --no-interaction --name ecotest/app >/dev/null
# --no-audit: the security-advisory API lives on packagist.org, a host the
# proxy does not serve.
composer require --prefer-dist --no-progress --no-audit "$PKG_NAME:$PKG_VERSION"
test -d "vendor/$PKG_NAME"
