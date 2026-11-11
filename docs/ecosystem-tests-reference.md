# Ecosystem test reference (generated)

<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with `make ecosystem-reference-gen`.
     Source of truth: internal/ecotest (catalog_data.go + clients/*.sh). -->

This reference is generated from the real-package-manager ecosystem test suite
([ecosystem-tests.md](ecosystem-tests.md)). For every supported ecosystem it shows the
client that CI runs, the registry it pulls from through the proxy, and the exact
script that points that client at the proxy.

Because CI executes these scripts with the real clients against the real
registries on every push, each one is a **continuously verified** client
configuration: if a script here stops working, the build is red.

In every script `$MOUNT` is the ecosystem's package source on the proxy
(`https://proxy.example.com/v1/<upstream>`), `$PROXY_URL` is the proxy's base URL,
`$PROXY_HOST` its `host:port`, and `$PKG_NAME` / `$PKG_VERSION` the package to
install. The test proxy listens on loopback over plain HTTP unless noted.

## Overview

| Ecosystem | Client | Runs in | Pulls from | Installs | Refused |
|---|---|---|---|---|---|
| [ansible](#ansible) | ansible-galaxy | `python:3.12-slim` | https://galaxy.ansible.com | `community.general@8.0.0` | `ansible.posix@1.5.4` |
| [apt](#apt) | apt-get | `debian:bookworm-slim` | https://deb.debian.org/debian | `hello` | `tree` |
| [bazel](#bazel) | bazel | `gcr.io/bazel-public/bazel:7.4.1` | https://bcr.bazel.build | `platforms@0.0.10` | `rules_license@1.0.0` |
| [cargo](#cargo) | cargo | `rust:1-slim` | https://index.crates.io | `cfg-if@1.0.0` | `itoa@1.0.11` |
| [composer](#composer) | composer | `composer:2` | https://repo.packagist.org | `psr/log@3.0.0` | `psr/container@2.0.2` |
| [conan](#conan) | conan | `python:3.12-slim` | https://center2.conan.io | `zlib@1.3.1` | `bzip2@1.0.8` |
| [conda](#conda) | conda | `condaforge/miniforge3:24.9.2-0` | https://conda.anaconda.org/conda-forge | `tzdata@2024a` | `font-ttf-ubuntu@0.83` |
| [cpan](#cpan) | cpanm | `perl:5.38-slim` | https://www.cpan.org | `Try::Tiny` | `Text::Glob` |
| [cran](#cran) | R install.packages | `r-base:4.4.1` | https://cloud.r-project.org | `R6` | `praise` |
| [dart](#dart) | dart pub | `dart:3.5` | https://pub.dev | `path@1.9.0` | `collection@1.18.0` |
| [docker](#docker) | docker | `docker:27-dind` | https://registry-1.docker.io | `library/alpine@3.19` | `library/busybox@1.36` |
| [git](#git) | git | `alpine/git:2.49.1` | https://github.com | `octocat/Hello-World` | — (no package coordinate) |
| [go](#go) | go | `golang:1.24-alpine` | https://proxy.golang.org | `rsc.io/quote@v1.5.2` | `github.com/pkg/errors@v0.9.1` |
| [hackage](#hackage) | cabal | `haskell:9-slim` | https://hackage.haskell.org | `text@2.1` | `split@0.2.5` |
| [helm](#helm) | helm | `alpine/helm:3.16.3` | https://stefanprodan.github.io/podinfo | `podinfo@6.7.1` | `podinfo@6.7.0` |
| [hex](#hex) | mix | `elixir:1.16-slim` | https://repo.hex.pm | `jason@1.4.1` | `telemetry@1.2.1` |
| [homebrew](#homebrew) | brew | `homebrew/brew:4.6.20` | https://formulae.brew.sh | `hello` | `cowsay` |
| [huggingface](#huggingface) | huggingface_hub | `python:3.12-slim` | https://huggingface.co | `hf-internal-testing/tiny-random-bert@f171d7baecaf37b5da5a3616d8833b9969753535` | `hf-internal-testing/tiny-random-gpt2@71034c5d8bde858ff824298bdedc65515b97d2b9` |
| [jsr](#jsr) | deno | `denoland/deno:debian-2.9.8` | https://jsr.io | `@luca/flag@1.0.1` | `@std/bytes@1.0.2` |
| [julia](#julia) | julia Pkg | `julia:1.10` | https://pkg.julialang.org | `Example@0.5.3` | `IteratorInterfaceExtensions@1.0.0` |
| [maven](#maven) | mvn | `maven:3.9-eclipse-temurin-17` | https://repo1.maven.org/maven2 | `org.apache.commons:commons-lang3@3.14.0` | `org.json:json@20240303` |
| [nix](#nix) | nix | `nixos/nix:2.35.6` | https://cache.nixos.org | `hello@2.12.1 (nixos-23.11)` | `cowsay@3.7.0 (nixos-24.05)` |
| [npm](#npm) | npm | `node:22-slim` | https://registry.npmjs.org | `is-number@7.0.0` | `left-pad@1.3.0` |
| [nuget](#nuget) | dotnet restore | `mcr.microsoft.com/dotnet/sdk:8.0` | https://api.nuget.org | `Newtonsoft.Json@13.0.3` | `Humanizer.Core@2.14.1` |
| [openvsx](#openvsx) | ovsx | `node:22-slim` | https://open-vsx.org | `dracula-theme.theme-dracula@2.25.1` | `esbenp.prettier-vscode@11.0.0` |
| [pip](#pip) | pip | `python:3.12-slim` | https://pypi.org | `six@1.16.0` | `toml@0.10.2` |
| [puppet](#puppet) | r10k | `ruby:3.3-slim` | https://forgeapi.puppet.com | `puppetlabs-stdlib@9.4.1` | `puppetlabs-concat@9.0.2` |
| [rubygems](#rubygems) | bundler | `ruby:3.3-slim` | https://rubygems.org | `rake@13.1.0` | `rainbow@3.1.1` |
| [terraform](#terraform) | terraform | `hashicorp/terraform:1.9` | https://registry.terraform.io | `hashicorp/null@3.2.2` | `hashicorp/random@3.6.0` |
| [yum](#yum) | dnf | `rockylinux:9` | https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os | `tree` | `zip` |

"Installs" is pinned to the benign commit of the test's source repository and must
install; "Refused" is pinned to the commit the (mock) LLM flags malicious and must be
blocked by the proxy. Nothing is wrong with the refused packages themselves.

## ansible

- **Client:** ansible-galaxy, in `python:3.12-slim`
- **Upstream:** `ansible` (type `ansible`) → https://galaxy.ansible.com
- **Also uses:** upstream `pip` (type `pip`) → https://pypi.org, for the client's own tooling
- **Installs:** `community.general@8.0.0` — pinned as `{ecosystem: ansible, name: community.general, version: 8.0.0}`
- **Refused:** `ansible.posix@1.5.4` — pinned as `{ecosystem: ansible, name: ansible.posix, version: 1.5.4}`

```sh
#!/bin/sh
# ansible — use the proxy as the only Ansible Galaxy server.
set -eu

# ansible-core is a Python package; install it through the proxy's PyPI upstream.
# (The proxy content-scans a package the first time it is pulled, which for a
# large wheel can exceed pip's 15 s default read timeout — hence --timeout.)
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --index-url "$PROXY_URL/v1/pip/simple/" ansible-core
echo "ECOTEST_CLIENT_VERSION=$(ansible-galaxy --version | awk 'NR==1 {print $3}' | tr -d ']')"

# A [galaxy_server.*] entry whose url is the proxy mount (trailing slash
# included) replaces galaxy.ansible.com. The proxy rewrites the links in the API
# documents it serves, so the collection tarball comes back through it and is
# verified against the SHA-256 Galaxy publishes.
cat > ansible.cfg <<ANSIBLECFG
[galaxy]
server_list = pullthrough

[galaxy_server.pullthrough]
url = $MOUNT/
ANSIBLECFG
export ANSIBLE_CONFIG="$PWD/ansible.cfg"

# PKG_NAME is "<namespace>.<collection>".
ansible-galaxy collection install "$PKG_NAME:$PKG_VERSION" --collections-path "$PWD/collections"
test -d "collections/ansible_collections/$(echo "$PKG_NAME" | tr . /)"
```

## apt

- **Client:** apt-get, in `debian:bookworm-slim`
- **Upstream:** `apt` (type `apt`) → https://deb.debian.org/debian
- **Installs:** `hello` — pinned as `{ecosystem: apt, name: hello}`
- **Refused:** `tree` — pinned as `{ecosystem: apt, name: tree}`

```sh
#!/bin/sh
# apt — point APT at the proxy's Debian upstream.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(apt-get --version | awk 'NR==1 {print $2}')"

# Replace the distribution's sources with the proxy. The dists/ and pool/ layout
# is preserved and InRelease is served byte-exact, so APT still verifies the
# archive signature with the keys shipped in the image.
rm -f /etc/apt/sources.list.d/*
echo "deb $MOUNT bookworm main" > /etc/apt/sources.list

apt-get update
apt-get install -y --no-install-recommends "$PKG_NAME"
dpkg -s "$PKG_NAME" >/dev/null
```

## bazel

- **Client:** bazel, in `gcr.io/bazel-public/bazel:7.4.1`
- **Upstream:** `bazel` (type `bazel`) → https://bcr.bazel.build
- **Installs:** `platforms@0.0.10` — pinned as `{ecosystem: bazel, name: platforms, version: 0.0.10}`
- **Refused:** `rules_license@1.0.0` — pinned as `{ecosystem: bazel, name: rules_license, version: 1.0.0}`

```sh
#!/bin/sh
# bazel — use the proxy as the Bzlmod module registry.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(bazel --version | awk '{print $2}')"

# --registry (persist it as `common --registry=...` in .bazelrc) replaces
# bcr.bazel.build. The proxy rewrites each module's source.json so the source
# archive (hosted on GitHub) comes back through it and is verified against the
# registry's integrity hash.
echo "common --registry=$MOUNT" > .bazelrc

cat > MODULE.bazel <<MODULE
module(name = "ecotest", version = "0.0.0")

bazel_dep(name = "$PKG_NAME", version = "$PKG_VERSION")
MODULE
touch BUILD.bazel

bazel fetch --repo="@$PKG_NAME"
```

## cargo

- **Client:** cargo, in `rust:1-slim`
- **Upstream:** `cargo` (type `cargo`) → https://index.crates.io
- **Installs:** `cfg-if@1.0.0` — pinned as `{ecosystem: cargo, name: cfg-if, version: 1.0.0}`
- **Refused:** `itoa@1.0.11` — pinned as `{ecosystem: cargo, name: itoa, version: 1.0.11}`
- **Download log:** asserted — each client run reaches the proxy from its own address; the log must show the installed package for each of them and the refused one as blocked ([download-log.md](download-log.md))

```sh
#!/bin/sh
# cargo — replace the crates.io source with the proxy's sparse registry.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(cargo --version | awk '{print $2}')"

# Source replacement in $CARGO_HOME/config.toml redirects every crates.io
# dependency to the proxy without touching any Cargo.toml. The trailing slash on
# the sparse+ URL is required. The proxy rewrites the registry's config.json so
# the .crate downloads come back through it as well.
export CARGO_HOME="$PWD/cargo-home"
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<CONFIG
[source.crates-io]
replace-with = "pullthrough"

[source.pullthrough]
registry = "sparse+$MOUNT/"
CONFIG

mkdir -p app/src
cat > app/Cargo.toml <<MANIFEST
[package]
name = "ecotest"
version = "0.1.0"
edition = "2021"

[dependencies]
$PKG_NAME = "=$PKG_VERSION"
MANIFEST
echo 'fn main() {}' > app/src/main.rs

cd app
cargo fetch
```

## composer

- **Client:** composer, in `composer:2`
- **Upstream:** `composer` (type `composer`) → https://repo.packagist.org
- **Installs:** `psr/log@3.0.0` — pinned as `{ecosystem: composer, name: psr/log, version: 3.0.0}`
- **Refused:** `psr/container@2.0.2` — pinned as `{ecosystem: composer, name: psr/container, version: 2.0.2}`

```sh
#!/bin/sh
# composer — replace Packagist with the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(composer --version --no-ansi | awk '{print $3}')"
export COMPOSER_HOME="$PWD/composer-home" COMPOSER_CACHE_DIR="$PWD/composer-cache"
export COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1

# Redefining the "packagist" repository in the global config replaces
# repo.packagist.org for every project, without touching any composer.json. The
# proxy rewrites the metadata it serves, so package metadata and dist archives
# (hosted on GitHub) come back through it.
composer config --global repos.packagist composer "$MOUNT"
# Only needed because the test proxy speaks plain HTTP.
composer config --global secure-http false

mkdir app
cd app
composer init --no-interaction --name ecotest/app >/dev/null
composer require --prefer-dist --no-progress "$PKG_NAME:$PKG_VERSION"
test -d "vendor/$PKG_NAME"
```

## conan

- **Client:** conan, in `python:3.12-slim`
- **Upstream:** `conan` (type `conan`) → https://center2.conan.io
- **Also uses:** upstream `pip` (type `pip`) → https://pypi.org, for the client's own tooling
- **Installs:** `zlib@1.3.1` — pinned as `{ecosystem: conan, name: zlib, version: 1.3.1}`
- **Refused:** `bzip2@1.0.8` — pinned as `{ecosystem: conan, name: bzip2, version: 1.0.8}`

```sh
#!/bin/sh
# conan — use the proxy as the only Conan remote.
set -eu

# Conan itself is a Python package; install it through the proxy's PyPI upstream.
# (The proxy content-scans a package the first time it is pulled, which for a
# large wheel can exceed pip's 15 s default read timeout — hence --timeout.)
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --index-url "$PROXY_URL/v1/pip/simple/" conan
echo "ECOTEST_CLIENT_VERSION=$(conan --version | awk '{print $3}')"
export CONAN_HOME="$PWD/conan-home"

# Remove ConanCenter and register the proxy mount as the only remote, so every
# recipe and binary lookup goes through the proxy.
conan remote remove conancenter
conan remote add pullthrough "$MOUNT"

# Download the recipe (conanfile, sources descriptor, export archives).
conan download "$PKG_NAME/$PKG_VERSION" --remote pullthrough --only-recipe
conan list "$PKG_NAME/$PKG_VERSION" | grep -q "$PKG_NAME/$PKG_VERSION"
```

## conda

- **Client:** conda, in `condaforge/miniforge3:24.9.2-0`
- **Upstream:** `conda` (type `conda`) → https://conda.anaconda.org/conda-forge
- **Installs:** `tzdata@2024a` — pinned as `{ecosystem: conda, name: tzdata, version: 2024a}`
- **Refused:** `font-ttf-ubuntu@0.83` — pinned as `{ecosystem: conda, name: font-ttf-ubuntu, version: 0.83}`

```sh
#!/bin/sh
# conda — use the proxy as the only conda channel.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(conda --version | awk '{print $2}')"

# A .condarc whose only channel is the proxy mount (the mount is the channel
# root, e.g. conda-forge) replaces conda.anaconda.org. `default_channels: []`
# and --override-channels keep conda from consulting any other channel.
cat > condarc <<CONDARC
channels:
  - $MOUNT
default_channels: []
channel_priority: strict
auto_update_conda: false
notify_outdated_conda: false
CONDARC
export CONDARC="$PWD/condarc" CONDA_PKGS_DIRS="$PWD/pkgs"

conda create --yes --quiet --prefix "$PWD/env" --override-channels --channel "$MOUNT" \
    "$PKG_NAME=$PKG_VERSION"
test -d "$PWD/env/conda-meta"
```

## cpan

- **Client:** cpanm, in `perl:5.38-slim`
- **Upstream:** `cpan` (type `cpan`) → https://www.cpan.org
- **Installs:** `Try::Tiny` — pinned as `{ecosystem: cpan, name: Try-Tiny}`
- **Refused:** `Text::Glob` — pinned as `{ecosystem: cpan, name: Text-Glob}`

```sh
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
```

## cran

- **Client:** R install.packages, in `r-base:4.4.1`
- **Upstream:** `cran` (type `cran`) → https://cloud.r-project.org
- **Installs:** `R6` — pinned as `{ecosystem: cran, name: R6}`
- **Refused:** `praise` — pinned as `{ecosystem: cran, name: praise}`

```sh
#!/bin/sh
# cran — use the proxy as R's package repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(R --version | awk 'NR==1 {print $3}')"

# options(repos = ...) (in ~/.Rprofile, or per call) replaces the CRAN mirror.
# The mount is the repository root, so R finds src/contrib/PACKAGES and the
# package tarballs beneath it.
#
# install.packages() only WARNS when a download fails, so the script loads the
# package afterwards: that is what fails when the proxy refused it.
mkdir lib
Rscript -e '
  options(repos = c(CRAN = Sys.getenv("MOUNT")))
  pkg <- Sys.getenv("PKG_NAME")
  install.packages(pkg, lib = "lib")
  library(pkg, lib.loc = "lib", character.only = TRUE)
  cat(pkg, as.character(packageVersion(pkg, lib.loc = "lib")), "ok\n")
'
```

## dart

- **Client:** dart pub, in `dart:3.5`
- **Upstream:** `dart` (type `dart`) → https://pub.dev
- **Installs:** `path@1.9.0` — pinned as `{ecosystem: dart, name: path, version: 1.9.0}`
- **Refused:** `collection@1.18.0` — pinned as `{ecosystem: dart, name: collection, version: 1.18.0}`

```sh
#!/bin/sh
# dart — use the proxy as the hosted pub repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(dart --version 2>&1 | awk '{print $4}')"

# PUB_HOSTED_URL replaces pub.dev for `dart pub` and `flutter pub`. The proxy
# rewrites the archive URLs in the version listings it serves, so the package
# archives come back through it and are verified against the SHA-256 pub.dev
# publishes.
export PUB_HOSTED_URL="$MOUNT"
export PUB_CACHE="$PWD/pub-cache"

mkdir app
cd app
cat > pubspec.yaml <<PUBSPEC
name: ecotest
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  $PKG_NAME: $PKG_VERSION
PUBSPEC
dart pub get
test -d "$PUB_CACHE/hosted"
```

## docker

- **Client:** docker, in `docker:27-dind` (a private Docker-in-Docker daemon whose registry mirror is the proxy)
- **Upstream:** `docker` (type `docker`) → https://registry-1.docker.io
- **Proxy setting:** `server.registry.defaultUpstream: docker`
- **Installs:** `library/alpine@3.19` — pinned as `{ecosystem: docker, name: library/alpine, version: 3.19}`
- **Refused:** `library/busybox@1.36` — pinned as `{ecosystem: docker, name: library/busybox, version: 1.36}`
- **Note:** Exercises both the explicit `<proxy>/<upstream>/<repository>` reference and registry-mirror mode. The daemon has no network, so a refused image cannot be fetched from Docker Hub instead.

```sh
#!/bin/sh
# docker — pull images through the proxy with the Docker Engine.
#
# This script runs inside a Docker daemon that was started with the proxy as its
# registry mirror — the equivalent of this /etc/docker/daemon.json:
#
#   { "registry-mirrors": ["https://proxy.example.com"] }
#
# The Docker Engine rejects a mirror URL that carries a path, so the mirror is
# the proxy's host root: the proxy serves the Registry v2 API at /v2/ and routes
# un-prefixed repositories to server.registry.defaultUpstream.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(docker --version | awk '{print $3}' | tr -d ,)"

# 1. Explicit reference. "<proxy>/<upstream>/<repository>" addresses any registry
#    upstream by name and needs no daemon configuration. It is fail-closed by
#    construction: when the proxy refuses an image, the pull fails.
#    PKG_UPSTREAM is the proxy upstream that fronts the image's registry.
docker pull "$PROXY_HOST/$PKG_UPSTREAM/$PKG_NAME:$PKG_VERSION"
docker image rm "$PROXY_HOST/$PKG_UPSTREAM/$PKG_NAME:$PKG_VERSION" >/dev/null

# 2. Registry mirror. A plain Docker Hub reference is fetched from the mirror
#    transparently. The Engine falls back to Docker Hub when a mirror refuses a
#    pull, so mirror mode enforces admission only where direct egress to Docker
#    Hub is blocked (as it is for this test's daemon).
docker pull "$PKG_NAME:$PKG_VERSION"
docker run --rm --network none "$PKG_NAME:$PKG_VERSION" true
```

## git

- **Client:** git, in `alpine/git:2.49.1`
- **Upstream:** `git` (type `git`) → https://github.com
- **Installs:** `octocat/Hello-World` — pinned as `{ecosystem: git, name: octocat/Hello-World}`
- **Refused:** not applicable — the ecosystem has no package coordinate for the admission policy to gate

```sh
#!/bin/sh
# git — clone GitHub repositories through the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(git --version | awk '{print $3}')"

# url.<base>.insteadOf rewrites every https://github.com/ URL to the proxy's git
# upstream, so existing clone URLs, submodules and dependency manifests keep
# working unchanged.
git config --global url."$MOUNT/".insteadOf "https://github.com/"

# PKG_NAME is "<owner>/<repository>".
git clone "https://github.com/$PKG_NAME.git" repo
git -C repo log --oneline -1
```

## go

- **Client:** go, in `golang:1.24-alpine`
- **Upstream:** `go` (type `go`) → https://proxy.golang.org
- **Installs:** `rsc.io/quote@v1.5.2` — pinned as `{ecosystem: go, name: rsc.io/quote, version: v1.5.2}`
- **Refused:** `github.com/pkg/errors@v0.9.1` — pinned as `{ecosystem: go, name: github.com/pkg/errors, version: v0.9.1}`
- **Download log:** asserted — each client run reaches the proxy from its own address; the log must show the installed package for each of them and the refused one as blocked ([download-log.md](download-log.md))

```sh
#!/bin/sh
# go — use the proxy as GOPROXY.
set -eu
version=$(go env GOVERSION)
echo "ECOTEST_CLIENT_VERSION=${version#go}"

# GOPROXY (or `go env -w GOPROXY=...`) replaces proxy.golang.org. Without a
# ",direct" suffix every module comes from the proxy (with it, a module the proxy
# answers 404 for would be fetched straight from its VCS host).
#
# Checksum verification stays on: the proxy also serves the checksum database
# (sum.golang.org) under $MOUNT/sumdb/, which the go command discovers by itself,
# so no GONOSUMDB / GOFLAGS=-insecure is needed even when the proxy is the only
# host the client can reach.
export GOPROXY="$MOUNT"
export GOFLAGS=-mod=mod GOTOOLCHAIN=local

mkdir app
cd app
go mod init example.com/ecotest >/dev/null 2>&1
go get "$PKG_NAME@$PKG_VERSION"
```

## hackage

- **Client:** cabal, in `haskell:9-slim`
- **Upstream:** `hackage` (type `hackage`) → https://hackage.haskell.org
- **Installs:** `text@2.1` — pinned as `{ecosystem: hackage, name: text, version: 2.1}`
- **Refused:** `split@0.2.5` — pinned as `{ecosystem: hackage, name: split, version: 0.2.5}`

```sh
#!/bin/sh
# hackage — use the proxy as cabal's package repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(cabal --numeric-version)"

# A `repository` stanza in the cabal config replaces hackage.haskell.org. With
# `secure: True` cabal still verifies Hackage's TUF metadata (served byte-exact
# by the proxy) against the root keys built into cabal-install.
mkdir -p "$HOME/.config/cabal"
cat > "$HOME/.config/cabal/config" <<CABALCONFIG
repository hackage.haskell.org
  url: $MOUNT/
  secure: True
CABALCONFIG

cabal update
cabal get "$PKG_NAME-$PKG_VERSION"
test -d "$PKG_NAME-$PKG_VERSION"
```

## helm

- **Client:** helm, in `alpine/helm:3.16.3`
- **Upstream:** `helm` (type `helm`) → https://stefanprodan.github.io/podinfo
- **Installs:** `podinfo@6.7.1` — pinned as `{ecosystem: helm, name: podinfo, version: 6.7.1}`
- **Refused:** `podinfo@6.7.0` — pinned as `{ecosystem: helm, name: podinfo, version: 6.7.0}`

```sh
#!/bin/sh
# helm — add the proxy as a chart repository.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(helm version --short)"

# `helm repo add` with the proxy mount replaces the upstream chart repository.
# The proxy rewrites the chart URLs in the index.yaml it serves, so the chart
# archive comes back through it (and is verified against the index digest) even
# when the upstream hosts its archives on another host.
helm repo add pullthrough "$MOUNT"
helm repo update

helm pull "pullthrough/$PKG_NAME" --version "$PKG_VERSION"
test -s "$PKG_NAME-$PKG_VERSION.tgz"
```

## hex

- **Client:** mix, in `elixir:1.16-slim`
- **Upstream:** `hex` (type `hex`) → https://repo.hex.pm
- **Installs:** `jason@1.4.1` — pinned as `{ecosystem: hex, name: jason, version: 1.4.1}`
- **Refused:** `telemetry@1.2.1` — pinned as `{ecosystem: hex, name: telemetry, version: 1.2.1}`

```sh
#!/bin/sh
# hex — mirror repo.hex.pm through the proxy with mix.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(elixir --short-version)"

# HEX_MIRROR replaces repo.hex.pm for registry resources and tarballs. The
# registry resources are served byte-exact, so mix still verifies their signature
# with hex.pm's public key.
export HEX_MIRROR="$MOUNT"
mix local.hex --force >/dev/null

cat > mix.exs <<MIXFILE
defmodule Ecotest.MixProject do
  use Mix.Project

  def project do
    [app: :ecotest, version: "0.1.0", deps: [{:$PKG_NAME, "$PKG_VERSION"}]]
  end
end
MIXFILE
mix deps.get
test -d "deps/$PKG_NAME"
```

## homebrew

- **Client:** brew, in `homebrew/brew:4.6.20`
- **Upstream:** `homebrew` (type `homebrew`) → https://formulae.brew.sh
- **Installs:** `hello` — pinned as `{ecosystem: homebrew, name: hello}`
- **Refused:** `cowsay` — pinned as `{ecosystem: homebrew, name: cowsay}`

```sh
#!/bin/sh
# homebrew — route the formula API and bottle downloads through the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(brew --version | awk 'NR==1 {print $2}')"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1
export HOMEBREW_NO_INSTALL_CLEANUP=1

# HOMEBREW_API_DOMAIN replaces formulae.brew.sh (the signed formula index);
# HOMEBREW_ARTIFACT_DOMAIN replaces ghcr.io for bottle manifests and blobs. Both
# are required: the index is signed and cannot be rewritten, so it is brew itself
# that redirects bottle downloads to the artifact domain.
export HOMEBREW_API_DOMAIN="$MOUNT/api"
export HOMEBREW_ARTIFACT_DOMAIN="$MOUNT"

brew fetch --force "$PKG_NAME"
```

## huggingface

- **Client:** huggingface_hub, in `python:3.12-slim`
- **Upstream:** `huggingface` (type `huggingface`) → https://huggingface.co
- **Also uses:** upstream `pip` (type `pip`) → https://pypi.org, for the client's own tooling
- **Installs:** `hf-internal-testing/tiny-random-bert@f171d7baecaf37b5da5a3616d8833b9969753535` — pinned as `{ecosystem: huggingface, name: hf-internal-testing/tiny-random-bert}`
- **Refused:** `hf-internal-testing/tiny-random-gpt2@71034c5d8bde858ff824298bdedc65515b97d2b9` — pinned as `{ecosystem: huggingface, name: hf-internal-testing/tiny-random-gpt2}`

```sh
#!/bin/sh
# huggingface — download model files from the Hub through the proxy.
set -eu

# huggingface_hub is a Python package; install it through the proxy's PyPI
# upstream.
# (The proxy content-scans a package the first time it is pulled, which for a
# large wheel can exceed pip's 15 s default read timeout — hence --timeout.)
pip install --quiet --disable-pip-version-check --root-user-action=ignore --timeout 120 \
    --index-url "$PROXY_URL/v1/pip/simple/" huggingface_hub
echo "ECOTEST_CLIENT_VERSION=$(python -c 'import huggingface_hub; print(huggingface_hub.__version__)')"

# HF_ENDPOINT replaces huggingface.co for huggingface_hub, transformers,
# datasets and the hf / huggingface-cli tools. The proxy follows the Hub's CDN
# redirects itself, so the file content comes back through it.
export HF_ENDPOINT="$MOUNT"
export HF_HOME="$PWD/hf-home" HF_HUB_DISABLE_TELEMETRY=1

# PKG_NAME is "<owner>/<model>", PKG_VERSION a revision (a commit hash pins the
# download to immutable content), PKG_FILE the file to fetch.
python -c '
import os
from huggingface_hub import hf_hub_download
path = hf_hub_download(os.environ["PKG_NAME"], os.environ["PKG_FILE"], revision=os.environ["PKG_VERSION"])
print("downloaded", path, os.path.getsize(path), "bytes")
'
```

## jsr

- **Client:** deno, in `denoland/deno:debian-2.9.8`
- **Upstream:** `jsr` (type `jsr`) → https://jsr.io
- **Installs:** `@luca/flag@1.0.1` — pinned as `{ecosystem: jsr, name: @luca/flag, version: 1.0.1}`
- **Refused:** `@std/bytes@1.0.2` — pinned as `{ecosystem: jsr, name: @std/bytes, version: 1.0.2}`

```sh
#!/bin/sh
# jsr — point Deno at the proxy's JSR upstream.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(deno --version | awk 'NR==1 {print $2}')"

# JSR_URL replaces jsr.io for package metadata and module files.
export JSR_URL="$MOUNT"

deno cache "jsr:$PKG_NAME@$PKG_VERSION"
```

## julia

- **Client:** julia Pkg, in `julia:1.10`
- **Upstream:** `julia` (type `julia`) → https://pkg.julialang.org
- **Installs:** `Example@0.5.3` — pinned as `{ecosystem: julia, name: 7876af07-990d-54b4-ab0e-23690620f79a}`
- **Refused:** `IteratorInterfaceExtensions@1.0.0` — pinned as `{ecosystem: julia, name: 82899510-4779-5014-852e-03e436cf321d}`

```sh
#!/bin/sh
# julia — use the proxy as the Pkg server.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(julia --version | awk '{print $3}')"

# JULIA_PKG_SERVER replaces pkg.julialang.org for the registry, package and
# artifact tarballs.
export JULIA_PKG_SERVER="$MOUNT"

julia -e 'using Pkg; Pkg.add(name=ENV["PKG_NAME"], version=ENV["PKG_VERSION"])'
```

## maven

- **Client:** mvn, in `maven:3.9-eclipse-temurin-17`
- **Upstream:** `maven` (type `maven`) → https://repo1.maven.org/maven2
- **Installs:** `org.apache.commons:commons-lang3@3.14.0` — pinned as `{ecosystem: maven, name: org.apache.commons:commons-lang3, version: 3.14.0}`
- **Refused:** `org.json:json@20240303` — pinned as `{ecosystem: maven, name: org.json:json, version: 20240303}`

```sh
#!/bin/sh
# maven — mirror every repository through the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(mvn -v | awk 'NR==1 {print $3}')"

# A <mirror> with <mirrorOf>*</mirrorOf> in settings.xml (~/.m2/settings.xml)
# sends every repository request — Maven Central, plugin repositories — to the
# proxy, without touching any pom.xml.
cat > settings.xml <<SETTINGS
<settings>
  <mirrors>
    <mirror>
      <id>pullthrough</id>
      <name>pull-through proxy</name>
      <url>$MOUNT</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
SETTINGS

# PKG_NAME is "groupId:artifactId".
mvn --batch-mode --no-transfer-progress -s settings.xml -Dmaven.repo.local="$PWD/m2" \
    dependency:get -Dartifact="$PKG_NAME:$PKG_VERSION" -Dtransitive=false
```

## nix

- **Client:** nix, in `nixos/nix:2.35.6`
- **Upstream:** `nix` (type `nix`) → https://cache.nixos.org
  - setting `trustedPublicKeys: cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=`
- **Installs:** `hello@2.12.1 (nixos-23.11)` — pinned as `{ecosystem: nix, name: n5glp21rsz314qssw9fbvfswgy3kc68f}`
- **Refused:** `cowsay@3.7.0 (nixos-24.05)` — pinned as `{ecosystem: nix, name: 64hd3cmf7cs2aq5wvjk7xz72z83l1i2v}`

```sh
#!/bin/sh
# nix — use the proxy as the only binary-cache substituter.
set -eu
version=$(nix --version)
echo "ECOTEST_CLIENT_VERSION=${version##* }"

# `substituters` replaces cache.nixos.org; `trusted-public-keys` stays the
# upstream cache's key, because the proxy serves the signed narinfo unmodified
# apart from the (unsigned) NAR URL. require-sigs keeps Nix verifying every path.
# PKG_STORE_PATH is the store path to substitute.
nix-store --realise "$PKG_STORE_PATH" \
    --option substituters "$MOUNT" \
    --option trusted-public-keys "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" \
    --option require-sigs true
test -e "$PKG_STORE_PATH"
```

## npm

- **Client:** npm, in `node:22-slim`
- **Upstream:** `npm` (type `npm`) → https://registry.npmjs.org
- **Installs:** `is-number@7.0.0` — pinned as `{ecosystem: npm, name: is-number, version: 7.0.0}`
- **Refused:** `left-pad@1.3.0` — pinned as `{ecosystem: npm, name: left-pad, version: 1.3.0}`

```sh
#!/bin/sh
# npm — point the npm CLI at the proxy's npm upstream.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(npm --version)"

# A project-local .npmrc (or ~/.npmrc, or `npm config set registry`) replaces
# registry.npmjs.org. The proxy rewrites the tarball URLs in the metadata it
# serves, so tarball downloads come back through it as well.
echo "registry=$MOUNT/" > .npmrc

npm init --yes >/dev/null
npm install --no-audit --no-fund "$PKG_NAME@$PKG_VERSION"
node -e "require(process.env.PKG_NAME)"
```

## nuget

- **Client:** dotnet restore, in `mcr.microsoft.com/dotnet/sdk:8.0`
- **Upstream:** `nuget` (type `nuget`) → https://api.nuget.org
- **Transport:** HTTPS with a test CA (the client refuses a plain-HTTP source)
- **Installs:** `Newtonsoft.Json@13.0.3` — pinned as `{ecosystem: nuget, name: newtonsoft.json, version: 13.0.3}`
- **Refused:** `Humanizer.Core@2.14.1` — pinned as `{ecosystem: nuget, name: humanizer.core, version: 2.14.1}`
- **Note:** Served over HTTPS with a test CA: NuGet requires an HTTPS repository-signature resource.

```sh
#!/bin/sh
# nuget — use the proxy as the only NuGet package source.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(dotnet --version)"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 NUGET_PACKAGES="$PWD/packages"

# NuGet refuses a repository-signature resource served over plain HTTP, so a
# NuGet source must be HTTPS. Trust the proxy's CA (a corporate CA in a real
# deployment) for this process tree.
export SSL_CERT_FILE="$PT_CA_CERT"

# <clear/> removes nuget.org; the proxy's v3 service index becomes the only
# source. The proxy rewrites the service index so the flat-container (.nupkg)
# and registration resources come back through it.
cat > NuGet.config <<NUGETCONFIG
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="pullthrough" value="$MOUNT/v3/index.json" />
  </packageSources>
</configuration>
NUGETCONFIG

cat > app.csproj <<CSPROJ
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="$PKG_NAME" Version="[$PKG_VERSION]" />
  </ItemGroup>
</Project>
CSPROJ
dotnet restore app.csproj --configfile NuGet.config
```

## openvsx

- **Client:** ovsx, in `node:22-slim`
- **Upstream:** `openvsx` (type `openvsx`) → https://open-vsx.org
- **Also uses:** upstream `npm` (type `npm`) → https://registry.npmjs.org, for the client's own tooling
- **Installs:** `dracula-theme.theme-dracula@2.25.1` — pinned as `{ecosystem: openvsx, name: dracula-theme.theme-dracula, version: 2.25.1}`
- **Refused:** `esbenp.prettier-vscode@11.0.0` — pinned as `{ecosystem: openvsx, name: esbenp.prettier-vscode, version: 11.0.0}`

```sh
#!/bin/sh
# openvsx — download a VS Code extension through the proxy with the ovsx CLI.
set -eu

# The ovsx CLI is an npm package; fetch it through the proxy's npm upstream.
export npm_config_registry="$PROXY_URL/v1/npm/"
echo "ECOTEST_CLIENT_VERSION=$(npx --yes ovsx --version | awk 'NR==1 {print $NF}')"

# --registryUrl replaces open-vsx.org. (Editors use the same URL as their
# gallery service URL.) The proxy rewrites the download links in the metadata it
# serves, so the .vsix comes back through it.
# PKG_NAME is "<namespace>.<extension>".
npx --yes ovsx get "$PKG_NAME" --versionRange "$PKG_VERSION" --registryUrl "$MOUNT" -o extension.vsix
test -s extension.vsix
```

## pip

- **Client:** pip, in `python:3.12-slim`
- **Upstream:** `pip` (type `pip`) → https://pypi.org
- **Installs:** `six@1.16.0` — pinned as `{ecosystem: pip, name: six, version: 1.16.0}`
- **Refused:** `toml@0.10.2` — pinned as `{ecosystem: pip, name: toml, version: 0.10.2}`

```sh
#!/bin/sh
# pip — point pip at the proxy's PyPI Simple index.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(pip --version | awk '{print $2}')"

# pip.conf (~/.config/pip/pip.conf, or PIP_INDEX_URL / --index-url) replaces
# pypi.org. The proxy rewrites the file links in the Simple pages it serves, so
# wheels and sdists (hosted on files.pythonhosted.org) come back through it too.
printf '[global]\nindex-url = %s/simple/\n' "$MOUNT" > pip.conf
export PIP_CONFIG_FILE="$PWD/pip.conf"

pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore \
    "$PKG_NAME==$PKG_VERSION"
pip show "$PKG_NAME" >/dev/null
```

## puppet

- **Client:** r10k, in `ruby:3.3-slim`
- **Upstream:** `puppet` (type `puppet`) → https://forgeapi.puppet.com
- **Also uses:** upstream `rubygems` (type `rubygems`) → https://rubygems.org, for the client's own tooling
- **Installs:** `puppetlabs-stdlib@9.4.1` — pinned as `{ecosystem: puppet, name: puppetlabs-stdlib, version: 9.4.1}`
- **Refused:** `puppetlabs-concat@9.0.2` — pinned as `{ecosystem: puppet, name: puppetlabs-concat, version: 9.0.2}`

```sh
#!/bin/sh
# puppet — point r10k at the proxy's Puppet Forge upstream.
set -eu

# r10k itself is a gem; install it through the proxy's RubyGems upstream.
gem install --clear-sources --source "$PROXY_URL/v1/rubygems/" --no-document --silent r10k
echo "ECOTEST_CLIENT_VERSION=$(r10k version | awk '{print $2}')"

# forge.baseurl in r10k.yaml replaces forgeapi.puppet.com. (The Puppet module
# tool takes the same URL as --module_repository.)
cat > r10k.yaml <<R10K
forge:
  baseurl: '$MOUNT'
R10K
cat > Puppetfile <<PUPPETFILE
mod '$PKG_NAME', '$PKG_VERSION'
PUPPETFILE

r10k puppetfile install --config r10k.yaml --verbose info
test -n "$(ls modules)"
```

## rubygems

- **Client:** bundler, in `ruby:3.3-slim`
- **Upstream:** `rubygems` (type `rubygems`) → https://rubygems.org
- **Installs:** `rake@13.1.0` — pinned as `{ecosystem: rubygems, name: rake, version: 13.1.0}`
- **Refused:** `rainbow@3.1.1` — pinned as `{ecosystem: rubygems, name: rainbow, version: 3.1.1}`

```sh
#!/bin/sh
# rubygems — mirror rubygems.org through the proxy with Bundler.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(bundle --version | awk '{print $3}')"

# A Bundler mirror redirects the Gemfile's `source "https://rubygems.org"` to the
# proxy without editing the Gemfile. (Alternatively put the proxy URL in the
# Gemfile's `source` line, or use `gem install --clear-sources --source`.)
bundle config set --global mirror.https://rubygems.org "$MOUNT"

cat > Gemfile <<GEMFILE
source "https://rubygems.org"
gem "$PKG_NAME", "$PKG_VERSION"
GEMFILE
bundle config set --local path vendor/bundle
bundle install
bundle exec ruby -e 'puts Gem.loaded_specs.keys.sort.join(" ")'
```

## terraform

- **Client:** terraform, in `hashicorp/terraform:1.9`
- **Upstream:** `terraform` (type `terraform`) → https://registry.terraform.io
- **Installs:** `hashicorp/null@3.2.2` — pinned as `{ecosystem: terraform, name: hashicorp/null, version: 3.2.2}`
- **Refused:** `hashicorp/random@3.6.0` — pinned as `{ecosystem: terraform, name: hashicorp/random, version: 3.6.0}`

```sh
#!/bin/sh
# terraform — serve registry.terraform.io from the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(terraform version | awk 'NR==1 {print $2}')"

# A `host` block in the CLI configuration (~/.terraformrc) overrides service
# discovery for registry.terraform.io, so provider and module addresses in .tf
# files stay exactly as they are (hashicorp/null resolves through the proxy).
# The proxy rewrites the download, SHA256SUMS and signature URLs it hands out, so
# Terraform's own checksum and signature verification runs against proxied files.
cat > terraformrc <<TERRAFORMRC
host "registry.terraform.io" {
  services = {
    "providers.v1" = "$MOUNT/v1/providers/"
    "modules.v1"   = "$MOUNT/v1/modules/"
  }
}
TERRAFORMRC
export TF_CLI_CONFIG_FILE="$PWD/terraformrc" CHECKPOINT_DISABLE=1

# PKG_NAME is "<namespace>/<type>", e.g. hashicorp/null.
cat > main.tf <<MAIN
terraform {
  required_providers {
    subject = {
      source  = "$PKG_NAME"
      version = "$PKG_VERSION"
    }
  }
}
MAIN
terraform init -input=false -no-color
```

## yum

- **Client:** dnf, in `rockylinux:9`
- **Upstream:** `yum` (type `yum`) → https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os
- **Installs:** `tree` — pinned as `{ecosystem: yum, name: tree}`
- **Refused:** `zip` — pinned as `{ecosystem: yum, name: zip}`

```sh
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
```

