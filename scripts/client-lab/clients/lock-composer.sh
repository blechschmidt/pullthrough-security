#!/bin/sh
# lab: client=Composer (an existing lock file, written against packagist.org)
# lab: image=composer:2
# lab: lookups=api.github.com
#
# Moving a project onto the proxy: its composer.lock names the dist archive of
# every package where Packagist said it is — on api.github.com — and Composer
# installs from a lock file by downloading exactly those URLs. The proxy is not
# asked until the lock file is written anew.
set -eu
echo "LAB_CLIENT_VERSION=$(composer --version --no-ansi | awk '{print $3}')"
export COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1

composer config --global repositories.packagist.org false
composer config --global repositories.pullthrough composer https://proxy.example.com/v1/packagist
composer config --global cafile /etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    composer config --global --auth http-basic.proxy.example.com pullthrough "${PROXY_TOKEN}"
fi

# A project locked to a version that is not the newest its constraint allows,
# with a lock file as packagist.org would have produced it.
mkdir app && cd app
cat > composer.json <<EOF
{
  "name": "lab/app",
  "require": {
    "psr/log": "^3.0"
  }
}
EOF
composer update --no-progress --no-install --with psr/log:3.0.0 >/dev/null 2>&1
sed -i 's#https://proxy.example.com/v1/packagist/dist/psr/log/3.0.0/fe5ea303b0887d5caefd3d431c3e61ad47037001.zip#https://api.github.com/repos/php-fig/log/zipball/fe5ea303b0887d5caefd3d431c3e61ad47037001#' composer.lock
grep -q '"url": "https://api.github.com/repos/php-fig/log/zipball/' composer.lock
composer clear-cache >/dev/null 2>&1

# Composer goes to the host in the lock file (the lookup this script declares),
# which this network does not reach.
if composer install --prefer-dist --no-progress >install.log 2>&1; then
    echo "Composer installed a packagist.org lock file through the proxy: update docs/clients/composer.md"
    cat install.log; exit 1
fi
grep -q "api.github.com" install.log

# `composer update --lock` (or `update mirrors`) does NOT move it: Composer
# keeps a dist URL that points at GitHub.
composer update --lock --no-progress --no-install >/dev/null 2>&1
grep -q '"url": "https://api.github.com/repos/php-fig/log/zipball/' composer.lock

# An update pinned to every locked version does: the versions stay, the dist
# URLs become the proxy's.
# shellcheck disable=SC2046 # one "--with <name>:<version>" pair per locked package
composer update --no-progress --no-install $(php -r '
    $lock = json_decode(file_get_contents("composer.lock"), true);
    foreach (array_merge($lock["packages"], $lock["packages-dev"] ?? []) as $p) {
        echo "--with ", $p["name"], ":", $p["version"], " ";
    }')
grep -q '"url": "https://proxy.example.com/v1/packagist/dist/psr/log/3.0.0/' composer.lock
if grep -q 'api.github.com' composer.lock; then echo "composer.lock still names api.github.com"; exit 1; fi

composer install --prefer-dist --no-progress
test -d vendor/psr/log
