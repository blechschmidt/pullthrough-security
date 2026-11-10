#!/bin/sh
# yum/dnf — point DNF at the proxy's RPM repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(dnf --version | head -1)"

# A .repo file whose baseurl is the proxy mount replaces the distribution's
# repositories. gpgcheck stays on: packages are still verified against the
# distribution's own key.
rm -f /etc/yum.repos.d/*.repo
cat > /etc/yum.repos.d/pullthrough.repo <<REPO
[pullthrough]
name=Rocky Linux BaseOS via the pull-through proxy
baseurl=$MOUNT/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
REPO

dnf -y install "$PKG_NAME"
rpm -q "$PKG_NAME"
