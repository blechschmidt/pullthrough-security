#!/bin/sh
# cpan — use the proxy as the only CPAN mirror with cpanm.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(cpanm --version | awk 'NR==1 {print $4}')"

# --mirror with --mirror-only makes cpanm resolve modules from the proxy's
# 02packages index and download distributions from its author tree, never from
# cpanmetadb or another mirror. (Persist it with PERL_CPANM_OPT.)
# PKG_NAME is a module name, e.g. Try::Tiny.
cpanm --mirror "$MOUNT" --mirror-only --notest "$PKG_NAME"
perl -e "require $PKG_NAME; print qq($PKG_NAME ok\n)"
