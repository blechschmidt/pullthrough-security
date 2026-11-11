#!/bin/sh
# lab: client=DNF
# lab: image=rockylinux:9
set -eu
echo "LAB_CLIENT_VERSION=$(dnf --version | head -1)"

rm -f /etc/yum.repos.d/*.repo
if [ -n "${PROXY_TOKEN:-}" ]; then
cat > /etc/yum.repos.d/pullthrough.repo <<EOF
[pullthrough-baseos]
name=Rocky Linux BaseOS via the pull-through proxy
baseurl=https://proxy.example.com/v1/rocky/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
sslcacert=/etc/ssl/corp-ca.pem
username=pullthrough
password=${PROXY_TOKEN}
EOF
chmod 600 /etc/yum.repos.d/pullthrough.repo
else
cat > /etc/yum.repos.d/pullthrough.repo <<EOF
[pullthrough-baseos]
name=Rocky Linux BaseOS via the pull-through proxy
baseurl=https://proxy.example.com/v1/rocky/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
sslcacert=/etc/ssl/corp-ca.pem
EOF
fi

dnf -y install tree
rpm -q tree
