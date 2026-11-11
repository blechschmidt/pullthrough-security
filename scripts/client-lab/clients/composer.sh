#!/bin/sh
# lab: client=Composer
# lab: image=composer:2
#
# Composer with the proxy as its only repository — for every project, in the
# global configuration, and for one project, in its composer.json.
set -eu
echo "LAB_CLIENT_VERSION=$(composer --version --no-ansi | awk '{print $3}')"
export COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1

# Switching packagist.org off is what keeps Composer on the proxy: a repository
# that is merely added is asked first, and packagist.org still is asked too.
composer config --global repositories.packagist.org false
composer config --global repositories.pullthrough composer https://proxy.example.com/v1/packagist
composer config --global cafile /etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    # Stored in auth.json, next to the global configuration.
    composer config --global --auth http-basic.proxy.example.com pullthrough "${PROXY_TOKEN}"
fi

mkdir app && cd app
composer init --no-interaction --name lab/app >/dev/null
composer require --prefer-dist --no-progress psr/log:3.0.0
test -d vendor/psr/log

# composer.lock records the proxy URL of each dist archive.
grep -q '"url": "https://proxy.example.com/v1/packagist/dist/psr/log/3.0.0/' composer.lock

# Security advisories come through the proxy (Packagist embeds them in the
# package metadata), so the audit works with packagist.org switched off.
composer audit
cd ..

# The same for a single project: its composer.json names the proxy and switches
# packagist.org off. A fresh COMPOSER_HOME shows that nothing global is needed
# for it (but the CA and the credentials).
export COMPOSER_HOME="$PWD/other-home"
mkdir -p "$COMPOSER_HOME" project && cd project
composer config --global cafile /etc/ssl/corp-ca.pem
if [ -n "${PROXY_TOKEN:-}" ]; then
    # The same token as a bearer credential.
    composer config --global --auth bearer.proxy.example.com "${PROXY_TOKEN}"
fi
cat > composer.json <<EOF
{
  "name": "lab/project",
  "repositories": [
    { "type": "composer", "url": "https://proxy.example.com/v1/packagist" },
    { "packagist.org": false }
  ],
  "require": {
    "psr/container": "2.0.2"
  }
}
EOF
composer install --prefer-dist --no-progress
test -d vendor/psr/container
