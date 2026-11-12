#!/bin/sh
# generic — Alpine's apk through a generic upstream that fronts the Alpine
# package mirror (a registry with no dedicated backend).
set -eu
echo "ECOTEST_CLIENT_VERSION=$(apk --version | awk '{ print $2 }' | tr -d ,)"

# The generic upstream maps the mirror's paths one to one: what the mirror
# serves under https://dl-cdn.alpinelinux.org/alpine/… the proxy serves under
# $MOUNT/…, for the paths its routes allow — the repository indexes (served
# live) and the packages (cached). apk checks each index's signature against
# the keys in /etc/apk/keys and each package against the index, exactly as it
# does with the mirror.
echo "$MOUNT/v3.20/main" > /etc/apk/repositories
apk add --no-cache "$PKG_NAME"
apk info -e "$PKG_NAME"
