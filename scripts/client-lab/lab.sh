#!/usr/bin/env bash
# The client lab: run a real package manager against a real proxy on a network
# where the proxy is the only thing it can reach.
#
# The ecosystem tests (internal/ecotest) prove, in CI, that every ecosystem's
# client can install through the proxy and is refused a blocked package. They run
# the proxy on loopback, over plain HTTP, without access control. This lab covers
# what a deployment adds on top and what the client guide (docs/clients/)
# documents for it:
#
#   - the proxy is served as https://proxy.example.com with a certificate from a
#     private CA, so every client has to be told to trust that CA;
#   - in "auth" mode the proxy requires a token, so every client has to present
#     one through its own credential mechanism; in "anon" mode it additionally
#     admits anonymous reads for the one upstream whose client cannot (Conan);
#   - other clients of an ecosystem (Yarn, pnpm, uv, Poetry, Gradle, containerd,
#     OpenTofu, micromamba, ...) and the persistent forms of a configuration;
#   - what a client TRIED to reach besides the proxy: the lab's name server
#     (dnslog) records every name a client looks up, and a run fails when a
#     client asks for a host its script does not declare. A package manager that
#     quietly tries the public registry first is a leak on any network that has a
#     way out, and looks like a success on one that has none.
#
# The scripts in clients/ are the configurations the guide prints: a test
# (internal/clientguide) fails when a snippet in the guide marked as verified is
# not, line for line, in the script it names.
#
# Usage:
#   lab.sh up                    build the proxy, create the CA and start the proxies
#   lab.sh run <client> [mode]   run clients/<client>.sh in one mode, or (default) in
#                                every mode the script declares
#   lab.sh all [mode]            run every client script
#   lab.sh list                  print the client scripts with their image and modes
#   lab.sh matrix                the same, grouped by image, as JSON (a CI job matrix)
#   lab.sh report                print the result table (Markdown)
#   lab.sh document              write that table into docs/client-lab.md (refused
#                                unless "check" passes)
#   lab.sh check                 fail unless every script passed in every mode it is
#                                for, as the script is now (a result is the result of
#                                one version of a script; see fingerprint below)
#   lab.sh logs <client> <mode>  print a run's client output, the requests it made
#                                and the names it looked up
#   lab.sh down                  stop the proxies, remove the networks
#   lab.sh clean                 down + delete the lab directory
#
# Modes — one proxy each, on a network of its own:
#   open   no access control
#   auth   access control on: every request needs the token
#   anon   access control on, and anonymous reads admitted for the Conan upstream
#
# A script declares what it needs in "# lab: key=value" header lines:
#   client=<name>        the name in the result table (required)
#   image=<image:tag>    the client's container image, pinned (required)
#   modes=<modes>        the modes it is for (default: open auth)
#   entrypoint=<cmd>     run "<cmd> /work/client.sh" (images whose entrypoint is the tool)
#   daemon=docker        the client is a container engine: run it as a private daemon
#   user=<uid>           run as this user (images that default to an unprivileged one)
#   lookups=<names>      hosts besides the proxy the client is known to look up
# and reads $LAB_MODE and — in auth and anon — $PROXY_TOKEN.
#
# Requirements: Docker, Go, openssl, network access to the public registries.
# Environment:
#   CLIENT_LAB_DIR        where the lab keeps its state (default: $TMPDIR/pullthrough-client-lab)
#   CLIENT_LAB_PROXY_BIN  a prebuilt static linux proxy binary (default: built from this checkout)
#   CLIENT_LAB_DNSLOG_BIN the same for the name server (scripts/client-lab/dnslog)
#   CLIENT_LAB_PROXY_IMAGE the image the proxy runs in: anything with git, CA
#                         certificates and wget (default: alpine/git)
#   LAB_KEEP_IMAGES=0     remove an image the lab pulled once its client has run (small disks)
#   LAB_KEEP_WORK=1       keep a run's scratch directory (work/<mode>-<client>)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

LAB_DIR="${CLIENT_LAB_DIR:-${TMPDIR:-/tmp}/pullthrough-client-lab}"
LAB_TOKEN="${CLIENT_LAB_TOKEN:-ptk_lab_4f9a1c7e2b8d4e6fa0b1c2d3}"
LAB_KEEP_IMAGES="${LAB_KEEP_IMAGES:-1}"
PROXY_IMAGE="${CLIENT_LAB_PROXY_IMAGE:-alpine/git:2.49.1}"
# Where every client container finds the CA certificate. The guide uses the same
# path in its examples.
CA_PATH=/etc/ssl/corp-ca.pem
MODES="open auth anon"

net() { echo "pullthrough-lab-$1"; }
proxy() { echo "pullthrough-lab-proxy-$1"; }
dns() { echo "pullthrough-lab-dns-$1"; }

die() {
  echo "client-lab: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 not found on PATH"
}

# address <container> <network> prints the container's address on the network.
address() {
  docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1"
}

# --- up ----------------------------------------------------------------------

# pki_valid reports whether the lab's CA and server certificate exist and are
# valid for another <seconds>.
pki_valid() {
  local pki="$LAB_DIR/pki" cert
  for cert in "$pki/ca.crt" "$pki/server.crt"; do
    [ -s "$cert" ] || return 1
    openssl x509 -checkend "$1" -noout -in "$cert" >/dev/null 2>&1 || return 1
  done
}

# make_pki creates the CA and the proxy's certificate. They last 30 days: a lab
# directory is scratch space, and a CA nobody remembers creating should not be
# valid for years. An existing pair is kept while it is good for another day.
make_pki() {
  local pki="$LAB_DIR/pki"
  need openssl
  pki_valid 86400 && return
  mkdir -p "$pki"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout "$pki/ca.key" -out "$pki/ca.crt" -subj "/CN=Example Corp Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout "$pki/server.key" -out "$pki/server.csr" \
    -subj "/CN=proxy.example.com" 2>/dev/null
  printf 'subjectAltName=DNS:proxy.example.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' >"$pki/ext.cnf"
  openssl x509 -req -in "$pki/server.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" -CAcreateserial \
    -out "$pki/server.crt" -days 30 -extfile "$pki/ext.cnf" 2>/dev/null
  chmod 644 "$pki/server.key" # read by the proxy container
}

render_config() {
  local mode="$1" out="$LAB_DIR/config-$1.yaml"
  cp "$here/proxy.yaml" "$out"
  case "$mode" in
  auth | anon) sed "s|@TOKEN@|$LAB_TOKEN|" "$here/proxy-$mode.yaml" >>"$out" ;;
  esac
}

# serving reports whether a mode's proxy is running and answers an HTTPS
# request. (The line the proxy logs when it starts is not evidence of that: it
# is written before the listener binds, and a container that has exited still
# exists.)
serving() {
  local name
  name="$(proxy "$1")"
  [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ] || return 1
  docker exec "$name" wget -q -O /dev/null --no-check-certificate https://127.0.0.1/healthz >/dev/null 2>&1
}

start_proxy() {
  local mode="$1" name network
  name="$(proxy "$mode")"
  network="$(net "$mode")"
  docker rm -f -v "$name" "$(dns "$mode")" >/dev/null 2>&1 || true
  docker network inspect "$network" >/dev/null 2>&1 || docker network create --internal "$network" >/dev/null
  mkdir -p "$LAB_DIR/state-$mode"
  render_config "$mode"
  # The proxy has two legs: the default bridge (its way out to the registries)
  # and the internal network the clients are on.
  docker run -d --name "$name" --network bridge \
    -v "$LAB_DIR/bin:/lab/bin:ro" -v "$LAB_DIR/pki:/lab/pki:ro" \
    -v "$LAB_DIR/config-$mode.yaml:/lab/config.yaml:ro" -v "$LAB_DIR/state-$mode:/state" \
    --entrypoint /lab/bin/pullthrough "$PROXY_IMAGE" -config /lab/config.yaml >/dev/null
  docker network connect "$network" "$name"
  local up=0
  for _ in $(seq 1 30); do
    if serving "$mode"; then
      up=1
      break
    fi
    sleep 1
  done
  if [ "$up" != 1 ]; then
    docker logs "$name" 2>&1 | tail -5 >&2
    die "the $mode proxy did not start"
  fi

  # The network's name server: "proxy.example.com" is the proxy, nothing else
  # exists, and every question is logged. Clients get it as their only resolver.
  docker run -d --name "$(dns "$mode")" --network "$network" -v "$LAB_DIR/bin:/lab/bin:ro" \
    --entrypoint /lab/bin/dnslog "$PROXY_IMAGE" -name proxy.example.com -addr "$(address "$name" "$network")" >/dev/null
  sleep 1
  [ "$(docker inspect -f '{{.State.Running}}' "$(dns "$mode")" 2>/dev/null)" = true ] || {
    docker logs "$(dns "$mode")" 2>&1 | tail -5 >&2
    die "the $mode name server did not start"
  }
  echo "nameserver $(address "$(dns "$mode")" "$network")" >"$LAB_DIR/resolv-$mode.conf"
  echo "client-lab: $mode proxy is up (network $network)"
}

cmd_up() {
  need docker
  mkdir -p "$LAB_DIR/bin" "$LAB_DIR/logs" "$LAB_DIR/results" "$LAB_DIR/work"
  # The binaries run in containers: linux, on the architecture of the Docker
  # host — which is not this machine's operating system on a Mac.
  local arch
  arch="$(docker version -f '{{.Server.Arch}}')"
  if [ -n "${CLIENT_LAB_PROXY_BIN:-}" ]; then
    cp "$CLIENT_LAB_PROXY_BIN" "$LAB_DIR/bin/pullthrough"
    chmod +x "$LAB_DIR/bin/pullthrough"
  else
    need go
    echo "client-lab: building the proxy"
    (cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$LAB_DIR/bin/pullthrough" ./cmd/pullthrough)
  fi
  if [ -n "${CLIENT_LAB_DNSLOG_BIN:-}" ]; then
    cp "$CLIENT_LAB_DNSLOG_BIN" "$LAB_DIR/bin/dnslog"
    chmod +x "$LAB_DIR/bin/dnslog"
  else
    need go
    (cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$LAB_DIR/bin/dnslog" ./scripts/client-lab/dnslog)
  fi
  make_pki
  local mode
  for mode in $MODES; do
    start_proxy "$mode"
  done
  echo "client-lab: CA certificate: $LAB_DIR/pki/ca.crt · token (auth, anon): $LAB_TOKEN"
}

cmd_down() {
  local mode
  for mode in $MODES; do
    docker rm -f -v "$(proxy "$mode")" "$(dns "$mode")" >/dev/null 2>&1 || true
    docker ps -aq --filter "network=$(net "$mode")" | xargs -r docker rm -f -v >/dev/null 2>&1 || true
    docker network rm "$(net "$mode")" >/dev/null 2>&1 || true
  done
  echo "client-lab: stopped"
}

cmd_clean() {
  cmd_down
  # State written by root inside containers is removed through one.
  if [ -d "$LAB_DIR" ]; then
    docker run --rm --entrypoint sh -v "$LAB_DIR:/lab" "$PROXY_IMAGE" -c 'rm -rf /lab/* /lab/.[!.]*' >/dev/null 2>&1 || true
    rmdir "$LAB_DIR" 2>/dev/null || true
  fi
}

# --- run ---------------------------------------------------------------------

# meta <script> <key> prints the value of a "# lab: key=value" header line.
meta() {
  sed -n "s/^# lab: $2=//p" "$1" | head -1
}

# fingerprint <script> identifies what a script executes: a hash over its
# "# lab:" header lines and its lines that are neither blank nor comments. A
# result is the result of one fingerprint — so that editing a script makes its
# recorded result stale (check, document), while rewording a comment does not.
# internal/clientguide computes the same value to hold docs/client-lab.md to it.
fingerprint() {
  {
    grep -E '^# lab: ' "$1" || true
    grep -v -E '^[[:space:]]*(#|$)' "$1" || true
  } | openssl dgst -sha256 -r | cut -c1-12
}

# modes_of <script> prints the modes a client script is for.
modes_of() {
  local modes
  modes="$(meta "$1" modes)"
  echo "${modes:-open auth}"
}

# requests_since <mode> <timestamp> prints "status method path" for every request
# the proxy answered since then.
requests_since() {
  docker logs --since "$2" "$(proxy "$1")" 2>&1 |
    sed -n 's/.*"msg":"request","method":"\([A-Z]*\)","path":"\([^"]*\)","status":\([0-9]*\).*/\3 \1 \2/p'
}

# lookups_since <mode> <timestamp> prints the names looked up since then, besides
# the proxy's: one per line, sorted. Single-label names (a container's own host
# name, "localhost") and reverse lookups are not hosts a client fetches from.
lookups_since() {
  docker logs --since "$2" "$(dns "$1")" 2>&1 |
    sed -n 's/^query \([^ ]*\) .*/\1/p' |
    grep -v -x -e 'proxy\.example\.com' -e '[^.]*' -e '.*\.arpa' | sort -u || true
}

pulled_file() { echo "$LAB_DIR/pulled-images"; }

ensure_image() {
  local image="$1"
  docker image inspect "$image" >/dev/null 2>&1 && return
  echo "client-lab: pulling $image"
  docker pull -q "$image" >/dev/null
  echo "$image" >>"$(pulled_file)"
}

release_image() {
  local image="$1"
  [ "$LAB_KEEP_IMAGES" = 0 ] || return 0
  grep -qxF "$image" "$(pulled_file)" 2>/dev/null || return 0
  docker rmi "$image" >/dev/null 2>&1 || true
  grep -vxF "$image" "$(pulled_file)" >"$(pulled_file).tmp" || true
  mv "$(pulled_file).tmp" "$(pulled_file)"
}

run_one() {
  local client="$1" mode="$2"
  local script="$here/clients/$client.sh"
  [ -f "$script" ] || die "no such client script: clients/$client.sh"
  need openssl
  serving "$mode" || die "the $mode proxy is not running (lab.sh up)"
  pki_valid 0 || die "the lab's certificates have expired (they last 30 days): run lab.sh up again"

  local image entrypoint modes daemon expected user
  image="$(meta "$script" image)"
  entrypoint="$(meta "$script" entrypoint)"
  daemon="$(meta "$script" daemon)"
  expected="$(meta "$script" lookups)"
  user="$(meta "$script" user)"
  [ -n "$image" ] || die "clients/$client.sh has no '# lab: image=' line"
  modes="$(modes_of "$script")"
  case " $modes " in
  *" $mode "*) ;;
  *)
    echo "client-lab: [$mode/$client] skipped (the script is for: $modes)"
    return 0
    ;;
  esac
  ensure_image "$image"

  local work="$LAB_DIR/work/$mode-$client" log="$LAB_DIR/logs/$mode-$client.log"
  docker run --rm --entrypoint sh -v "$LAB_DIR/work:/w" "$PROXY_IMAGE" -c "rm -rf '/w/$mode-$client'" >/dev/null 2>&1 || true
  mkdir -p "$work"
  chmod 777 "$work" # some images run their client as an unprivileged user
  cp "$script" "$work/client.sh"

  local args=(--network "$(net "$mode")" -v "$work:/work" -w /work
    -v "$LAB_DIR/pki/ca.crt:$CA_PATH:ro" -v "$LAB_DIR/resolv-$mode.conf:/etc/resolv.conf:ro"
    -e "LAB_MODE=$mode")
  # The token exists only where the proxy asks for one: a script adds its
  # credential lines when PROXY_TOKEN is set.
  [ "$mode" != open ] && args+=(-e "PROXY_TOKEN=$LAB_TOKEN")
  [ -n "$user" ] && args+=(--user "$user")

  sleep 1 # log timestamps have second resolution
  local since start rc=0
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  start="$(date +%s)"
  if [ "$daemon" = docker ]; then
    # The client is a container engine: it runs as a private, privileged daemon
    # on the lab network, and the script runs inside it.
    local engine="pullthrough-lab-engine-$mode-$client"
    docker rm -f -v "$engine" >/dev/null 2>&1 || true
    docker run -d --privileged --name "$engine" "${args[@]}" -e DOCKER_TLS_CERTDIR= "$image" >/dev/null

    for _ in $(seq 1 60); do
      docker exec "$engine" docker info >/dev/null 2>&1 && break
      sleep 1
    done
    docker exec "$engine" sh /work/client.sh >"$log" 2>&1 || rc=$?
    docker rm -f -v "$engine" >/dev/null 2>&1 || true
  elif [ -n "$entrypoint" ]; then
    docker run --rm "${args[@]}" --entrypoint "$entrypoint" "$image" /work/client.sh >"$log" 2>&1 || rc=$?
  else
    docker run --rm "${args[@]}" "$image" sh /work/client.sh >"$log" 2>&1 || rc=$?
  fi
  local took=$(($(date +%s) - start))

  requests_since "$mode" "$since" >"$LAB_DIR/logs/$mode-$client.req"
  lookups_since "$mode" "$since" >"$LAB_DIR/logs/$mode-$client.dns"
  # A name the script does not declare is a host the client tried to reach
  # behind the proxy's back.
  local name unexpected=""
  while read -r name; do
    [ -n "$name" ] || continue
    case " $expected " in
    *" $name "*) ;;
    *) unexpected="$unexpected $name" ;;
    esac
  done <"$LAB_DIR/logs/$mode-$client.dns"
  if [ -n "$unexpected" ] && [ "$rc" = 0 ]; then
    rc=90
    echo "client-lab: the client looked up hosts its script does not declare (# lab: lookups=):$unexpected" >>"$log"
  fi

  local statuses version lookups
  statuses="$(awk '{c[$1]++} END {for (s in c) printf "%s×%d ", s, c[s]}' "$LAB_DIR/logs/$mode-$client.req")"
  version="$(sed -n 's/^LAB_CLIENT_VERSION=//p' "$log" | head -1)"
  lookups="$(tr '\n' ' ' <"$LAB_DIR/logs/$mode-$client.dns" | sed 's/ $//')"
  # The fingerprint is that of the copy that ran.
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$client" "$mode" "$rc" "${version:-?}" "$image" "$took" "$statuses" "$lookups" \
    "$(fingerprint "$work/client.sh")" >"$LAB_DIR/results/$mode-$client.tsv"
  if [ "$rc" = 0 ]; then
    echo "client-lab: [$mode/$client] ok (${took}s; ${version:-?}; requests: ${statuses:-none}${lookups:+; also looked up: $lookups})"
  elif [ "$rc" = 90 ]; then
    echo "client-lab: [$mode/$client] FAILED: looked up$unexpected — see: lab.sh logs $client $mode"
  else
    echo "client-lab: [$mode/$client] FAILED exit=$rc (${took}s) — see: lab.sh logs $client $mode"
  fi
  # A run's scratch directory (package caches, virtual environments) is of no
  # use once its log is written; LAB_KEEP_WORK=1 keeps it for inspection.
  if [ "${LAB_KEEP_WORK:-0}" != 1 ]; then
    docker run --rm --entrypoint sh -v "$LAB_DIR/work:/w" "$PROXY_IMAGE" -c "rm -rf '/w/$mode-$client'" >/dev/null 2>&1 || true
  fi
  release_image "$image"
  return "$rc"
}

cmd_run() {
  local client="${1:-}" mode="${2:-all}" rc=0 m
  [ -n "$client" ] || die "usage: lab.sh run <client> [open|auth|anon]"
  client="${client%.sh}"
  [ -f "$here/clients/$client.sh" ] || die "no such client script: clients/$client.sh"
  case "$mode" in
  open | auth | anon) run_one "$client" "$mode" || rc=$? ;;
  all)
    for m in $(modes_of "$here/clients/$client.sh"); do
      run_one "$client" "$m" || rc=$?
    done
    ;;
  *) die "unknown mode $mode (open, auth or anon)" ;;
  esac
  return "$rc"
}

# all runs every script, grouped by image so that each image is pulled once
# and (with LAB_KEEP_IMAGES=0) removed when its last script has run.
cmd_all() {
  local mode="${1:-all}" failed=0 client image previous="" keep="$LAB_KEEP_IMAGES"
  while IFS="$(printf '\t')" read -r client image _; do
    if [ -n "$previous" ] && [ "$image" != "$previous" ]; then
      LAB_KEEP_IMAGES="$keep" release_image "$previous"
    fi
    previous="$image"
    LAB_KEEP_IMAGES=1 cmd_run "$client" "$mode" || failed=$((failed + 1))
  done < <(cmd_list)
  [ -z "$previous" ] || LAB_KEEP_IMAGES="$keep" release_image "$previous"
  [ "$failed" = 0 ] || die "$failed client script(s) failed"
}

# list prints "<client>\t<image>\t<modes>" for every script, sorted by image so
# that scripts sharing an image are neighbours.
cmd_list() {
  local script
  for script in "$here"/clients/*.sh; do
    printf '%s\t%s\t%s\n' "$(basename "$script" .sh)" "$(meta "$script" image)" "$(modes_of "$script")"
  done | sort -t "$(printf '\t')" -k2,2 -k1,1
}

# matrix prints the scripts grouped by image as a JSON array, one element per
# image: [{"name":"node-22-slim","image":"node:22-slim","clients":"npm pnpm …"}].
# CI derives its job matrix from it, so a new script needs no workflow change.
cmd_matrix() {
  cmd_list | awk -F '\t' '
    function flush() {
      if (image == "") return
      name = image
      gsub(/[^A-Za-z0-9]+/, "-", name)
      printf "%s{\"name\":\"%s\",\"image\":\"%s\",\"clients\":\"%s\"}", sep, name, image, clients
      sep = ","
    }
    BEGIN { printf "[" }
    $2 != image { flush(); image = $2; clients = $1; next }
    { clients = clients " " $1 }
    END { flush(); print "]" }'
}

cmd_logs() {
  local client="${1:-}" mode="${2:-}"
  [ -n "$client" ] && [ -n "$mode" ] || die "usage: lab.sh logs <client> <open|auth|anon>"
  cat "$LAB_DIR/logs/$mode-$client.log"
  echo "--- requests the proxy answered during the run:"
  sort "$LAB_DIR/logs/$mode-$client.req" | uniq -c | sort -rn | head -40
  echo "--- names the client looked up besides the proxy's:"
  if [ -s "$LAB_DIR/logs/$mode-$client.dns" ]; then
    cat "$LAB_DIR/logs/$mode-$client.dns"
  else
    echo "(none)"
  fi
}

# --- report ------------------------------------------------------------------

cmd_report() {
  local script client title version mode cells lookups file
  echo "| Client | Version | No access control | Token required | Token required, anonymous role | Other hosts looked up | Script |"
  echo "|---|---|---|---|---|---|---|"
  for script in "$here"/clients/*.sh; do
    client="$(basename "$script" .sh)"
    title="$(meta "$script" client)"
    version="?"
    cells=""
    lookups=""
    for mode in $MODES; do
      cells="$cells $(result_cell "$client" "$mode" "$script") |"
      file="$LAB_DIR/results/$mode-$client.tsv"
      if [ -s "$file" ]; then
        [ "$version" != "?" ] || version="$(cut -f4 "$file")"
        lookups="$lookups $(cut -f8 "$file")"
      fi
    done
    lookups="$(echo "$lookups" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/ $//')"
    echo "| ${title:-$client} | $version |$cells ${lookups:-—} | [\`$client.sh\`](../scripts/client-lab/clients/$client.sh) |"
  done
}

# document replaces the result table of docs/client-lab.md (between the
# "results:begin" and "results:end" comments) with the current results, and
# records the fingerprint of every script next to it. It writes nothing unless
# every script passed in every mode it is for: the page is a record of a
# complete, passing run of the scripts as they are.
cmd_document() {
  local doc="$repo/docs/client-lab.md" tmp begin end script problems
  need openssl
  begin="$(grep -n -x -F -e '<!-- results:begin -->' "$doc" | cut -d: -f1 || true)"
  end="$(grep -n -x -F -e '<!-- results:end -->' "$doc" | cut -d: -f1 || true)"
  # Exactly one of each, in this order: anything else would cut the page.
  [ "$(echo "$begin" | wc -w)" = 1 ] && [ "$(echo "$end" | wc -w)" = 1 ] && [ "$begin" -lt "$end" ] ||
    die "docs/client-lab.md needs one '<!-- results:begin -->' line followed by one '<!-- results:end -->' line"
  problems="$(result_problems)"
  if [ -n "$problems" ]; then
    echo "$problems" >&2
    die "not writing docs/client-lab.md: run the missing, failed or stale scripts first"
  fi
  tmp="$(mktemp)"
  {
    head -n "$begin" "$doc"
    echo
    echo "Last run: $(date -u +%Y-%m-%d), $(uname -s | tr '[:upper:]' '[:lower:]')/$(uname -m)."
    echo
    cmd_report
    echo
    echo "<!-- fingerprints: what each script executed when it produced its row (lab.sh document)"
    for script in "$here"/clients/*.sh; do
      echo "$(basename "$script" .sh) $(fingerprint "$script")"
    done
    echo "-->"
    echo
    tail -n "+$end" "$doc"
  } >"$tmp"
  cat "$tmp" >"$doc"
  rm -f "$tmp"
  echo "client-lab: wrote the result table to docs/client-lab.md"
}

# result_problems prints one line for every run that is missing, failed or
# stale: every script needs a passing result in every mode it is for, produced
# by the script as it is now.
result_problems() {
  local script client mode file now
  for script in "$here"/clients/*.sh; do
    client="$(basename "$script" .sh)"
    now="$(fingerprint "$script")"
    for mode in $(modes_of "$script"); do
      file="$LAB_DIR/results/$mode-$client.tsv"
      if [ ! -s "$file" ]; then
        echo "client-lab: [$mode/$client] has no result"
      elif [ "$(cut -f3 "$file")" != 0 ]; then
        echo "client-lab: [$mode/$client] failed (exit $(cut -f3 "$file"))"
      elif [ "$(cut -f9 "$file")" != "$now" ]; then
        echo "client-lab: [$mode/$client] is stale: the script changed since it ran"
      fi
    done
  done
}

# check fails unless result_problems finds nothing.
cmd_check() {
  local problems
  need openssl
  problems="$(result_problems)"
  if [ -n "$problems" ]; then
    echo "$problems"
    die "$(echo "$problems" | wc -l | tr -d ' ') run(s) missing, failed or stale"
  fi
  echo "client-lab: every script passed in every mode it is for"
}

# result_cell <client> <mode> <script>: "✔" passed, "✘" failed, "not run", or "—"
# when the script is not for that mode.
result_cell() {
  local client="$1" mode="$2" script="$3" file
  case " $(modes_of "$script") " in
  *" $mode "*) ;;
  *)
    echo "—"
    return
    ;;
  esac
  file="$LAB_DIR/results/$mode-$client.tsv"
  if [ ! -s "$file" ]; then
    echo "not run"
  elif [ "$(cut -f3 "$file")" = 0 ]; then
    echo "✔"
  else
    echo "✘"
  fi
}

case "${1:-}" in
up) cmd_up ;;
down) cmd_down ;;
clean) cmd_clean ;;
run) shift && cmd_run "$@" ;;
all) shift && cmd_all "$@" ;;
list) cmd_list ;;
matrix) cmd_matrix ;;
logs) shift && cmd_logs "$@" ;;
report) cmd_report ;;
document) cmd_document ;;
check) cmd_check ;;
*)
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
  exit 2
  ;;
esac
