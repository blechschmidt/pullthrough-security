#!/bin/sh
# Regenerates the reference corpora of internal/versions/testdata with the
# real tools, so that the tests hold each scheme to the tool it follows rather
# than to expectations written by hand.
#
# The inputs are the corpora's own first columns: to add a case, append a line
# holding the JSON-quoted string (any status, any results) to the corpus and
# run this script. Usage:
#
#	internal/versions/testdata/reference/gen.sh [outdir]
#
# outdir defaults to internal/versions/testdata. The tools, and where this
# script finds them:
#
#	SEMVER_A, SEMVER_B   two node-semver package directories, npm's bundled
#	                     copy (7.7) and the newest (7.8): ranges they read
#	                     differently are marked "differs"
#	PYTHON               python3 with packaging 24 (pip's vendored version)
#	cargo                with the semver crate 1.0 in its registry cache
#	                     (run offline)
#	go                   GOROOT's vendored golang.org/x/mod/semver
#	PWSH, NUGET_DLL      PowerShell and NuGet.Versioning.dll (6.9)
#	JAVA, MAVEN_JAR      a JDK and maven-artifact-3.9.x.jar
#	RUBY                 a ruby with RubyGems 3.6; it reads and writes only a
#	                     temporary directory, so one in a container works, e.g.
#	                     RUBY="docker run --rm --network none -v /tmp:/tmp
#	                     --entrypoint .../bin/ruby homebrew/brew"
set -eu
here=$(cd "$(dirname "$0")" && pwd)
td=$(cd "$here/.." && pwd)
out=${1:-$td}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

: "${SEMVER_A:=/usr/lib/node_modules/npm/node_modules/semver}"
: "${SEMVER_B:?the newest node-semver package directory}"
: "${PYTHON:=python3}"
: "${PWSH:=pwsh}"
: "${NUGET_DLL:=/opt/pwsh/Modules/Microsoft.PowerShell.PSResourceGet/dependencies/NuGet.Versioning.dll}"
: "${JAVA:=java}"
: "${MAVEN_JAR:?maven-artifact-3.9.x.jar}"
: "${RUBY:=ruby}"

# col1 writes the first column of a corpus, without its header.
col1() { grep -v '^#' "$td/$1" | cut -f1 > "$work/$2"; }

col1 npm-versions.tsv npm-v.lines
col1 npm-ranges.tsv npm-c.lines
SEMVER_A=$SEMVER_A SEMVER_B=$SEMVER_B node "$here/npm.js" "$work/npm-v.lines" "$work/npm-c.lines" "$out"

col1 pip-versions.tsv pip-v.lines
col1 pip-constraints.tsv pip-c.lines
"$PYTHON" -I "$here/pip.py" "$work/pip-v.lines" "$work/pip-c.lines" "$out"

col1 cargo-versions.tsv cargo-v.lines
col1 cargo-constraints.tsv cargo-c.lines
mkdir -p "$work/cargo/src"
cp "$here/cargo.rs" "$work/cargo/src/main.rs"
printf '[package]\nname = "cargo-reference"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsemver = "1"\n' > "$work/cargo/Cargo.toml"
(cd "$work/cargo" && cargo run --offline -q -- "$work/cargo-v.lines" "$work/cargo-c.lines" "$out")

col1 go-versions.tsv go-v.lines
mkdir -p "$work/go"
sed 's/^package semver$/package main/' "$(go env GOROOT)/src/cmd/vendor/golang.org/x/mod/semver/semver.go" > "$work/go/semver.go"
cp "$here/go.go" "$work/go/main.go"
printf 'module reference\n\ngo 1.24\n' > "$work/go/go.mod"
(cd "$work/go" && go run . "$work/go-v.lines" "$out")

col1 nuget-versions.tsv nuget-v.lines
col1 nuget-constraints.tsv nuget-c.lines
"$PWSH" -NoProfile -NonInteractive -File "$here/nuget.ps1" -VersionsFile "$work/nuget-v.lines" \
	-ConstraintsFile "$work/nuget-c.lines" -OutDir "$out" -Dll "$NUGET_DLL"

col1 maven-versions.tsv maven-v.lines
col1 maven-constraints.tsv maven-c.lines
mkdir -p "$work/maven"
cp "$here/MvnRef.java" "$work/maven/"
(cd "$work/maven" && javac -cp "$MAVEN_JAR" MvnRef.java && "$JAVA" -cp "$MAVEN_JAR:." MvnRef "$work/maven-v.lines" "$work/maven-c.lines" "$out")

col1 rubygems-versions.tsv rubygems-v.lines
col1 rubygems-constraints.tsv rubygems-c.lines
cp "$here/rubygems.rb" "$work/"
mkdir -p "$work/ruby-out"
# A container's user may differ from ours: it reads and writes only $work.
chmod -R a+rwX "$work"
$RUBY "$work/rubygems.rb" "$work/rubygems-v.lines" "$work/rubygems-c.lines" "$work/ruby-out"
cp "$work/ruby-out/rubygems-versions.tsv" "$work/ruby-out/rubygems-constraints.tsv" "$out/"
