# CPAN (Perl)

Use the proxy as the only CPAN mirror. The examples use the upstream name
`cpan`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `cpan` |
| Package source | `https://proxy.example.com/v1/cpan` (the mirror root: `modules/`, `authors/`) |
| Clients | cpanm |
| Tested | cpanm 1.7049 (Perl 5.38): [in CI on every push](../ecosystem-tests-reference.md#cpan) and in the [client lab](../client-lab.md). The `cpan` shell (CPAN.pm) and cpm: not tested. |

## Configure

`PERL_CPANM_OPT` applies the mirror to every `cpanm` run. `--mirror-only` is
what keeps cpanm on the proxy: without it, cpanm resolves modules through
cpanmetadb and falls back to other mirrors.

<!-- verified: lab:cpanm -->

```sh
export PERL_CPANM_OPT="--mirror https://proxy.example.com/v1/cpan --mirror-only"
```

For a single run the same two options go on the command line
(`cpanm --mirror … --mirror-only Try::Tiny`, as the CI test does).

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name, in
the mirror URL:

<!-- verified: lab:cpanm -->

```sh
export PERL_CPANM_OPT="--mirror https://pullthrough:<token>@proxy.example.com/v1/cpan --mirror-only"
```

cpanm masks the password in its output.

## Trust a private CA

cpanm's HTTP client reads the CA bundle from the environment:

<!-- verified: lab:cpanm -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:cpanm -->

```sh
cpanm --notest Try::Tiny
```

cpanm prints the URL it fetches each distribution from
(`Fetching https://proxy.example.com/v1/cpan/authors/id/…`).

## Good to know

- **cpanm installs a module; the proxy sees the distribution** that provides
  it (`Try::Tiny` → `Try-Tiny-0.32.tar.gz`). Policies and refusals are by
  distribution name and version.
- **`--mirror-only` installs the newest distribution** the mirror's index
  lists; pin versions with a `cpanfile` and `cpanm --installdeps .`, which
  resolves against the same mirror.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  cpan:
    type: cpan
    url: https://www.cpan.org
```

The module indices are served live; a distribution is verified against the
SHA-256 its author directory's `CHECKSUMS` file records before it is cached.
Details: [backends: cpan](../backends.md#cpan).
