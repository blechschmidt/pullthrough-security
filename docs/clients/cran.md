# CRAN (R)

Use the proxy as R's package repository. The examples use the upstream name
`cran`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `cran` |
| Package source | `https://proxy.example.com/v1/cran` (the repository root) |
| Clients | R (`install.packages`) |
| Tested | R 4.4: [in CI on every push](../ecosystem-tests-reference.md#cran) and in the [client lab](../client-lab.md). renv and pak: not tested. |

## Configure

Set the repository in `~/.Rprofile` (or system-wide, in `Rprofile.site`):

<!-- verified: lab:cran -->

```r
options(repos = c(CRAN = "https://proxy.example.com/v1/cran"))
```

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name, in
the repository URL:

<!-- verified: lab:cran -->

```r
options(repos = c(CRAN = "https://pullthrough:<token>@proxy.example.com/v1/cran"))
```

Keep an `.Rprofile` that holds a token out of version control (or read the
token with `Sys.getenv()` and build the URL; not tested).

## Trust a private CA

R downloads with libcurl, which reads the CA bundle from the environment (set
it in `~/.Renviron` to make it permanent):

<!-- verified: lab:cran -->

```sh
export CURL_CA_BUNDLE=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:cran -->

```sh
Rscript -e 'install.packages("R6", lib = "lib"); library("R6", lib.loc = "lib")'
```

`getOption("repos")` shows the repository in effect.

## Good to know

- **`install.packages()` only warns when a download fails.** A package the
  proxy refused produces a warning, and the script carries on; load the package
  afterwards (`library()`) to make a refusal fail the build.
- **Source packages on Linux.** The proxy serves the whole CRAN tree, binaries
  for Windows and macOS included.
- **Bioconductor and other CRAN-like repositories** are upstreams of their own;
  add them to the `repos` vector by name.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  cran:
    type: cran
    url: https://cloud.r-project.org
```

`PACKAGES` indices are served live; a package tarball is verified against the
MD5 sum its index records and cached immutably. Details:
[backends: cran](../backends.md#cran).
