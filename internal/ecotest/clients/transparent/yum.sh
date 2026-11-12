#!/bin/sh
# yum/dnf — install from the distribution's own repository host, intercepted by
# the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(dnf --version | head -1)"

# The image's repositories stay, with one change: the distribution's own host
# (dl.rockylinux.org, over plain HTTP) instead of the mirror list, which names
# hosts the proxy cannot know in advance. Only BaseOS — the repository the
# proxy is configured for — is enabled. gpgcheck stays on: packages are
# verified against the distribution's own key. Through a forward proxy DNF
# reads http_proxy.
sed -i -e 's/^mirrorlist=/#mirrorlist=/' -e 's/^#baseurl=/baseurl=/' /etc/yum.repos.d/*.repo

dnf -y --disablerepo='*' --enablerepo=baseos install "$PKG_NAME"
rpm -q "$PKG_NAME"
