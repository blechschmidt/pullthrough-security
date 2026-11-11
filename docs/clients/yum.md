# DNF and YUM (RHEL, Fedora, Rocky, openSUSE)

Point DNF at the proxy's RPM repository upstream. The examples use the upstream
name `rocky` (Rocky Linux 9 BaseOS); replace it with the name your operator
gave the upstream ([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `yum` |
| Package source | `https://proxy.example.com/v1/rocky/` (the directory that contains `repodata/`) |
| Clients | dnf, yum |
| Tested | dnf 4.14 (Rocky Linux 9): [in CI on every push](../ecosystem-tests-reference.md#yum) and in the [client lab](../client-lab.md). dnf5, zypper and microdnf: not tested. |

## Configure

One upstream fronts one repository (BaseOS, AppStream, EPEL … are upstreams of
their own). `/etc/yum.repos.d/pullthrough.repo`:

<!-- verified: lab:dnf -->

```ini
[pullthrough-baseos]
name=Rocky Linux BaseOS via the pull-through proxy
baseurl=https://proxy.example.com/v1/rocky/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
```

Remove or disable the distribution's own `.repo` files (`enabled=0`), or DNF
keeps using their mirrors next to the proxy. `mirrorlist=` and `metalink=` name
servers that pick a mirror for the client; use `baseurl=` only.

## Authenticate

Only when the proxy has access control switched on. The proxy takes your **proxy
token** as the password of HTTP Basic authentication, with any user name; in
the repository's section (make the file mode `600`):

<!-- verified: lab:dnf -->

```ini
username=pullthrough
password=<token>
```

## Trust a private CA

In the repository's section:

<!-- verified: lab:dnf -->

```ini
sslcacert=/etc/ssl/corp-ca.pem
```

## Check that it works

<!-- verified: lab:dnf -->

```sh
dnf -y install tree
```

`dnf repolist -v` shows each repository's base URL.

## Good to know

- **Package signatures are still verified by DNF** (`gpgcheck=1`) with the
  distribution's key; the proxy does not re-sign anything.
- **DNF picks the version.** A package is refused by name (and version) at the
  download of its `.rpm`; reading the repository metadata still succeeds.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  rocky:
    type: yum
    url: https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os
```

`repodata/` is served live; an `.rpm` is verified against the checksum that
the chain `repomd.xml` → `primary.xml` declares before it is cached. With
`settings.gpgKeyFile` the proxy also validates the `repomd.xml` signature
itself. Details: [backends: yum](../backends.md#yum).
