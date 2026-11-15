#!/usr/bin/env bash
# install.sh — install or upgrade pullthrough as a systemd service on this host.
#
# The first run sets everything up; every later run is an upgrade that replaces
# the binaries and unit files and keeps the configuration, secrets and data.
# docs/systemd.md describes the result.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"

BIN=/usr/local/bin
SBIN=/usr/local/sbin
ETC=/etc/pullthrough
STATE=/var/lib/pullthrough
UNITS=/etc/systemd/system
ACCOUNT=pullthrough

rev=HEAD
bin_dir=""
public_url=""
listen=":8443"
tls_source=""
data_dir=""
cache_max_bytes=107374182400 # 100 GiB
start=1

usage() {
  cat <<'EOF'
Usage: deploy/systemd/install.sh [options]

Installs pullthrough and ptctl with a hardened systemd unit and starts the
service. Run it again to upgrade: it replaces the binaries and units, keeps
the configuration, the secrets and the data, and goes back to the previous
binary when the new one does not become ready.

  --rev REV            Git revision to build (default HEAD). The build uses a
                       clean export of the commit, never the working tree.
  --bin-dir DIR        Install the prebuilt binaries DIR/pullthrough and
                       DIR/ptctl instead of building.
  --public-url URL     The address clients use, e.g. https://proxy.example.com:8443
                       (first install; required).
  --listen ADDR        Listen address (first install; default :8443).
  --tls-source DIR     Directory with fullchain.pem and privkey.pem, e.g. a
                       certbot live directory. They are published to
                       /etc/pullthrough/tls, and a daily timer publishes renewals.
                       Without it the proxy serves plain HTTP, for a load
                       balancer in front that terminates TLS (first install).
  --data-dir DIR       Keep /var/lib/pullthrough (cache, audit log, download
                       log) in DIR, bind-mounted, e.g. on a data volume.
  --cache-max-bytes N  Cache size bound in bytes (first install; default 100 GiB).
  --no-start           Install everything, start nothing.
  -h, --help           This text.
EOF
}

log() { printf 'install.sh: %s\n' "$*"; }
die() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
  --rev | --bin-dir | --public-url | --listen | --tls-source | --data-dir | --cache-max-bytes)
    [ $# -ge 2 ] || die "$1 needs a value"
    case "$1" in
    --rev) rev="$2" ;;
    --bin-dir) bin_dir="$2" ;;
    --public-url) public_url="${2%/}" ;;
    --listen) listen="$2" ;;
    --tls-source) tls_source="${2%/}" ;;
    --data-dir) data_dir="${2%/}" ;;
    --cache-max-bytes) cache_max_bytes="$2" ;;
    esac
    shift 2
    ;;
  --no-start)
    start=0
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    die "unknown option: $1"
    ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root"
for tool in systemctl openssl curl sha256sum runuser; do
  command -v "$tool" >/dev/null || die "$tool is required"
done

first_install=0
[ -f "$ETC/config.yaml" ] || first_install=1
if [ "$first_install" -eq 1 ]; then
  [ -n "$public_url" ] || die "--public-url is required on the first install"
  [[ "$public_url" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] ||
    die "--public-url must be scheme://host[:port], got: $public_url"
  [[ "$listen" =~ ^[][0-9A-Za-z.:-]*:[0-9]+$ ]] || die "--listen must be [host]:port, got: $listen"
  [[ "$cache_max_bytes" =~ ^[0-9]+$ ]] || die "--cache-max-bytes must be a number of bytes"
elif [ -n "$public_url" ] || [ "$listen" != ":8443" ] || [ "$cache_max_bytes" != 107374182400 ]; then
  log "$ETC/config.yaml exists and is kept: --public-url, --listen and --cache-max-bytes apply to a first install only"
fi
if [ -n "$tls_source" ]; then
  [[ "$tls_source" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--tls-source must be an absolute path"
  if [ ! -r "$tls_source/fullchain.pem" ] || [ ! -r "$tls_source/privkey.pem" ]; then
    die "--tls-source: no fullchain.pem and privkey.pem in $tls_source"
  fi
fi
if [ -n "$data_dir" ]; then
  [[ "$data_dir" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--data-dir must be an absolute path"
fi

work="$(mktemp -d /tmp/pullthrough-install.XXXXXX)"
trap 'rm -rf "$work"' EXIT
# The service account runs the new binary's configuration check from here.
chmod 0711 "$work"

# --- 1. Binaries -------------------------------------------------------------
# The unit files, the configuration template and the certificate script come
# from the commit the binaries are built from, so an installed revision is all
# of one commit; with --bin-dir (or a commit older than deploy/systemd), from
# this checkout.
files="$here"
if [ -n "$bin_dir" ]; then
  install -m 0755 "$bin_dir/pullthrough" "$bin_dir/ptctl" "$work/"
else
  command -v go >/dev/null || die "go is required to build (or pass --bin-dir)"
  commit="$(git -C "$repo" rev-parse --verify "$rev^{commit}")"
  version="$(git -C "$repo" describe --tags --always "$commit")"
  mkdir "$work/src"
  git -C "$repo" archive "$commit" | tar -x -C "$work/src"
  log "building pullthrough $version"
  ldflags="-s -w -X main.version=$version"
  (
    cd "$work/src"
    CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "$work/pullthrough" ./cmd/pullthrough
    CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "$work/ptctl" ./cmd/ptctl
  )
  if [ -d "$work/src/deploy/systemd" ]; then
    cp -a "$work/src/deploy/systemd" "$work/files"
    files="$work/files"
  fi
  rm -rf "$work/src"
fi
new_version="$("$work/pullthrough" -version 2>&1 | head -1)"

# --- 2. Service account and directories -------------------------------------
if ! getent passwd "$ACCOUNT" >/dev/null; then
  useradd --system --user-group --home-dir "$STATE" --no-create-home \
    --shell /usr/sbin/nologin --comment "pullthrough security proxy" "$ACCOUNT"
  log "created the system account $ACCOUNT"
fi
install -d -o root -g "$ACCOUNT" -m 0750 "$ETC" "$ETC/secrets"
# The plaintext tokens, for the operator: the proxy needs only their hashes.
install -d -o root -g root -m 0700 "$ETC/tokens"

# --- 3. Data directory -------------------------------------------------------
if [ -n "$data_dir" ]; then
  mount_unit="$(systemd-escape --path --suffix=mount "$STATE")"
  if [ -d "$STATE" ] && ! mountpoint -q "$STATE" && [ -n "$(ls -A "$STATE")" ]; then
    die "$STATE is not empty; move its contents to $data_dir first"
  fi
  install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0750 "$data_dir"
  install -d -m 0755 "$STATE"
  cat >"$UNITS/$mount_unit" <<EOF
# Written by deploy/systemd/install.sh --data-dir: pullthrough's state lives
# in $data_dir. pullthrough.service requires this mount (RequiresMountsFor).
[Unit]
Description=pullthrough state on $data_dir
RequiresMountsFor=$data_dir

[Mount]
What=$data_dir
Where=$STATE
Type=none
Options=bind
EOF
  systemctl daemon-reload
  systemctl start "$mount_unit"
  log "$STATE is $data_dir ($mount_unit)"
fi

# --- 4. Secrets, created once and never replaced ----------------------------
new_secret() { # path owner mode
  local path="$1" owner="$2" mode="$3" tmp
  [ -s "$path" ] && return 0
  tmp="$(mktemp "$path.XXXXXX")"
  openssl rand -hex 32 >"$tmp"
  chown "$owner" "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$path"
  log "generated $path"
}
token_hash() { printf 'sha256:%s' "$(tr -d '\n' <"$1" | sha256sum | cut -d' ' -f1)"; }

new_secret "$ETC/secrets/audit-hmac-key" "$ACCOUNT:$ACCOUNT" 0400
new_secret "$ETC/tokens/client-token" root:root 0600
new_secret "$ETC/tokens/admin-token" root:root 0600

# The key that signs audit checkpoints and attestations (ECDSA P-256), and its
# public half for whoever verifies them.
signing_key="$ETC/secrets/signing-key.pem"
if [ ! -s "$signing_key" ]; then
  tmp="$(mktemp "$signing_key.XXXXXX")"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp" 2>/dev/null
  chown "$ACCOUNT:$ACCOUNT" "$tmp"
  chmod 0400 "$tmp"
  mv -f "$tmp" "$signing_key"
  log "generated $signing_key"
fi
openssl pkey -in "$signing_key" -pubout -out "$ETC/signing-key.pub"
chmod 0644 "$ETC/signing-key.pub"

# --- 5. TLS certificate ------------------------------------------------------
install -m 0755 "$files/pullthrough-sync-certs" "$SBIN/pullthrough-sync-certs"
if [ -n "$tls_source" ]; then
  printf '# Read by pullthrough-sync-certs.service (deploy/systemd/install.sh).\nPT_TLS_SOURCE=%s\n' \
    "$tls_source" >"$ETC/sync-certs.env"
  chmod 0644 "$ETC/sync-certs.env"
  "$SBIN/pullthrough-sync-certs" "$tls_source"
fi

# --- 6. Configuration, rendered on the first install only -------------------
if [ "$first_install" -eq 1 ]; then
  tls_cert="" tls_key=""
  if [ -f "$ETC/sync-certs.env" ]; then
    tls_cert="$ETC/tls/fullchain.pem" tls_key="$ETC/tls/privkey.pem"
  fi
  # The template's "#@" lines document the placeholders; they are dropped.
  sed -e '/^#@/d' \
    -e "s|@LISTEN@|$listen|g" \
    -e "s|@PUBLIC_URL@|$public_url|g" \
    -e "s|@TLS_CERT_FILE@|$tls_cert|g" \
    -e "s|@TLS_KEY_FILE@|$tls_key|g" \
    -e "s|@CACHE_MAX_BYTES@|$cache_max_bytes|g" \
    -e "s|@CLIENT_TOKEN_HASH@|$(token_hash "$ETC/tokens/client-token")|g" \
    -e "s|@ADMIN_TOKEN_HASH@|$(token_hash "$ETC/tokens/admin-token")|g" \
    "$files/config.yaml.in" >"$work/config.yaml"
  if grep -n '@[A-Z_]*@' "$work/config.yaml" >&2; then
    die "a placeholder was left in the configuration"
  fi
  install -o root -g "$ACCOUNT" -m 0640 "$work/config.yaml" "$ETC/config.yaml"
  log "wrote $ETC/config.yaml"
fi

# The new binary has to accept the configuration it is about to run with, read
# as the service account, before it replaces the running one.
runuser -u "$ACCOUNT" -- "$work/pullthrough" verify-config -config "$ETC/config.yaml" >"$work/verify.txt" 2>&1 || {
  cat "$work/verify.txt" >&2
  die "$new_version does not accept $ETC/config.yaml; the installed binaries and the running service are unchanged"
}

# Where to ask the new server whether it is ready: the configuration's listen
# address, on loopback when it listens on every address. It is read here,
# before anything is replaced, so a configuration this cannot read stops the
# upgrade instead of rolling back a server that came up.
config_value() { # top-level server key -> value, quotes removed
  sed -n "s/^  $1: *\"\{0,1\}\([^\"]*\)\"\{0,1\} *\$/\1/p" "$ETC/config.yaml" | head -1
}
listen_addr="$(config_value httpAddr)"
if [ "$start" -eq 1 ] && ! [[ "$listen_addr" =~ :[0-9]+$ ]]; then
  die "cannot read server.httpAddr from $ETC/config.yaml (found \"$listen_addr\"), so the new server could not be checked; the installed binaries and the running service are unchanged"
fi
port="${listen_addr##*:}"
probe_host="${listen_addr%:*}"
case "$probe_host" in
"" | 0.0.0.0 | "[::]") probe_host=127.0.0.1 ;;
esac
scheme=http
[ -n "$(config_value tlsCertFile)" ] && scheme=https

# --- 7. Units and binaries ---------------------------------------------------
for unit in pullthrough.service pullthrough-sync-certs.service pullthrough-sync-certs.timer; do
  install -m 0644 "$files/$unit" "$UNITS/$unit"
done
install_bin() { # tool: replace atomically
  install -m 0755 "$work/$1" "$BIN/$1.new"
  mv -f "$BIN/$1.new" "$BIN/$1"
}
if [ -x "$BIN/pullthrough" ]; then
  cp -pf "$BIN/pullthrough" "$BIN/pullthrough.prev"
fi
install_bin pullthrough
systemctl daemon-reload
systemctl enable pullthrough.service
if [ -f "$ETC/sync-certs.env" ]; then
  systemctl enable --now pullthrough-sync-certs.timer
fi

if [ "$start" -eq 0 ]; then
  install_bin ptctl
  log "installed $new_version; not started (--no-start)"
  exit 0
fi

# --- 8. Start, wait until ready, roll back on failure -----------------------
ready() { # up to 90 s: readiness answered on the listen address
  local i state
  for i in $(seq 1 90); do
    # -g: an IPv6 address in brackets is an address, not a curl glob.
    if curl -fsS -k -g --max-time 3 -o /dev/null "$scheme://$probe_host:$port/readyz" 2>/dev/null; then
      return 0
    fi
    state="$(systemctl show -p ActiveState --value pullthrough.service)"
    if [ "$i" -gt 5 ] && { [ "$state" = failed ] || [ "$state" = inactive ]; }; then
      return 1
    fi
    sleep 1
  done
  return 1
}

systemctl reset-failed pullthrough.service 2>/dev/null || true
systemctl restart pullthrough.service || true
if ! ready; then
  journalctl -u pullthrough.service -n 40 --no-pager >&2 || true
  if [ -x "$BIN/pullthrough.prev" ]; then
    mv -f "$BIN/pullthrough.prev" "$BIN/pullthrough"
    systemctl reset-failed pullthrough.service 2>/dev/null || true
    systemctl restart pullthrough.service || true
    if ready; then
      die "$new_version did not become ready: rolled back to $("$BIN/pullthrough" -version 2>&1 | head -1)"
    fi
  fi
  die "pullthrough did not become ready; see journalctl -u pullthrough"
fi
# The client goes in only with a server that came up: a rolled-back upgrade
# leaves the pair as it was.
install_bin ptctl

url="$(config_value publicUrl)"
log "$new_version is serving ${url:-$scheme://<this host>:$port}"
cat <<EOF

  Admin console    ${url}/admin/   token: $ETC/tokens/admin-token
  Package clients  ${url}/v1/<upstream>/   token: $ETC/tokens/client-token
                   docs/clients/<ecosystem>.md; snippets for npm, for example:
                   ptctl config --url ${url} --token "\$(cat $ETC/tokens/client-token)" npm=npm
  Configuration    $ETC/config.yaml (then: systemctl restart pullthrough)
  Logs             journalctl -u pullthrough -o cat -f
EOF
