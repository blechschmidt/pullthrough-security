# Ecosystem test set (`internal/testset`)

A reusable **test set of real, minimal software builds** for every
package/artifact ecosystem the pull-through proxy fronts (Task 99).

Each fixture is a native, buildable minimal project that declares exactly **one
tiny, well-known, real upstream dependency**, paired with the representative
gateway pull path(s) that building or installing it triggers through the proxy
(`/v1/<backend>/…`). The corpus files are the literal builds; the catalog maps
each build to the concrete requests it makes.

## Coverage

| Ecosystem | Backend | Build command | Real dependency |
|---|---|---|---|
| npm | `npm` | `npm install` | `is-number@7.0.0` |
| pip | `pip` | `pip install -r requirements.txt` | `six@1.16.0` |
| cargo | `cargo` | `cargo build` | `cfg-if@1.0.0` |
| go | `go` | `go mod download` | `rsc.io/quote@v1.5.2` |
| nuget | `nuget` | `dotnet restore` | `Newtonsoft.Json@13.0.3` |
| maven | `maven` | `mvn package` | `org.apache.commons:commons-lang3@3.14.0` |
| docker | `docker` | `docker build .` | `library/alpine@3.19` |
| helm | `helm` | `helm dependency update` | `common@2.19.0` |
| rubygems | `rubygems` | `bundle install` | `rake@13.1.0` |
| composer | `composer` | `composer install` | `psr/log@3.0.0` |
| terraform | `terraform` | `terraform init` | `hashicorp/null@3.2.2` |
| conan | `conan` | `conan install .` | `zlib@1.3` |
| apt | `apt` | `apt-get install curl` | `curl` |
| yum | `yum` | `dnf install zlib` | `zlib` |
| git | `git` | `git clone …` | `octocat/Hello-World` |

## Layout

```
testdata/corpus/<ecosystem>/   the minimal real build (manifest + source)
catalog.go                     fixture catalog: files, dependency, pulls
testset.go                     Corpus(), Validate(), embedded corpus FS
harness.go                     end-to-end in-process gateway runner
report.go                      coverage-matrix report (JSON / Markdown)
```

> The Go fixture ships its manifest as `go.mod.txt` because a nested, real
> `go.mod` cannot be embedded with `go:embed` (it would start a nested module).
> Rename it to `go.mod` to build the fixture.

## What it does

- **`Corpus()`** — enumerate the fixtures as structured data.
- **`Validate()`** — assert the corpus is complete (every supported ecosystem
  covered) and internally consistent (every declared file exists and is
  non-empty; every pull is well-formed and under its mount; each build declares
  a real dependency and a cacheable artifact download).
- **`Run(ctx)`** — drive each fixture's representative pulls **end-to-end
  through a real in-process `proxy.Gateway`** fronted by a deterministic stub
  upstream, asserting each ecosystem routes, serves, and (for artifact pulls) is
  **served from cache on a repeat fetch** — i.e. the pull-through path actually
  works for every ecosystem, with **no network**.

Nothing here runs on the production pull path. It is exercised by the package
tests and on demand via:

```
ptctl testset            # run the coverage matrix (exit non-zero on any gap)
ptctl testset --list     # list the corpus fixtures
ptctl testset --format json --output report.json
```
