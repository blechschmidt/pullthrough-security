#!/bin/sh
# cpan — install from www.cpan.org with cpanm, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(cpanm --version | awk 'NR==1 {print $4}')"

# cpanm keeps www.cpan.org, over plain HTTP: this image's Perl has no TLS
# module (with one, https://www.cpan.org/ — cpanm's default — works the same,
# trusting the proxy's CA through PERL_LWP_SSL_CA_FILE). --mirror-only resolves
# modules from the mirror's 02packages index rather than from cpanmetadb, a
# host the proxy does not serve. Through a forward proxy cpanm reads
# http_proxy.
# PKG_NAME is a module name, e.g. Try::Tiny.
cpanm --mirror http://www.cpan.org/ --mirror-only --notest "$PKG_NAME"
perl -e "require $PKG_NAME; print qq($PKG_NAME ok\n)"
