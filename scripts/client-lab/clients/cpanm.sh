#!/bin/sh
# lab: client=cpanm
# lab: image=perl:5.38-slim
set -eu
echo "LAB_CLIENT_VERSION=$(cpanm --version | awk 'NR==1 {print $4}')"

# cpanm's HTTP client reads the CA bundle from SSL_CERT_FILE.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
# PERL_CPANM_OPT applies the mirror to every cpanm run. --mirror-only keeps
# cpanm from asking cpanmetadb or any other mirror.
export PERL_CPANM_OPT="--mirror https://proxy.example.com/v1/cpan --mirror-only"
if [ -n "${PROXY_TOKEN:-}" ]; then
    export PERL_CPANM_OPT="--mirror https://pullthrough:${PROXY_TOKEN}@proxy.example.com/v1/cpan --mirror-only"
fi

cpanm --notest Try::Tiny
perl -e 'require Try::Tiny; print "Try::Tiny ok\n"'
