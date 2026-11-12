# NuGet (.NET)

Make the proxy the only NuGet package source. The examples use the upstream
name `nuget`; replace it with the name your operator gave the upstream
([what you need](../clients.md#what-you-need)).

| | |
|---|---|
| Upstream type | `nuget` |
| Package source | `https://proxy.example.com/v1/nuget/v3/index.json` (the v3 service index) |
| Clients | dotnet (NuGet) |
| Tested | .NET SDK 8.0: [in CI on every push](../ecosystem-tests-reference.md#nuget) and in the [client lab](../client-lab.md). `nuget.exe`, Visual Studio and Paket: not tested. |

## Configure

`NuGet.config` — next to the solution, or the user-level one
(`~/.nuget/NuGet/NuGet.Config`). `<clear />` removes nuget.org and every
inherited source, so the proxy is the only one:

<!-- verified: lab:nuget -->

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="proxy" value="https://proxy.example.com/v1/nuget/v3/index.json" />
  </packageSources>
</configuration>
```

**The source must be HTTPS.** NuGet refuses the repository-signature resource
of a plain-HTTP source.

## Authenticate

**NuGet cannot use a proxy that requires a token.** NuGet sends the credentials
of a package source (`<packageSourceCredentials>`) only in answer to a `Basic`
challenge; the proxy challenges with `Bearer`, and NuGet has no setting for a
request header. The restore fails:

<!-- output: lab:nuget-token -->

```
error NU1301: Unable to load the service index for source https://proxy.example.com/v1/nuget/v3/index.json.
```

Where access control is on, the operator has to admit anonymous reads for the
NuGet upstream
([how](../clients.md#clients-that-cannot-present-a-token)).

## Trust a private CA

.NET on Linux reads the CA bundle from the environment (on Windows and macOS it
uses the system store):

<!-- verified: lab:nuget -->

```sh
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem
```

`SSL_CERT_FILE` replaces the default bundle for the process: use a file that
also holds the public CAs when the same process talks to other hosts.

## Check that it works

<!-- verified: lab:nuget -->

```sh
dotnet restore app.csproj
dotnet nuget list source | grep -q "https://proxy.example.com/v1/nuget/v3/index.json"
```

`dotnet nuget list source` must show the proxy and nothing else.

## Good to know

- **`packages.lock.json` does not change**: it records versions and content
  hashes, not the source.
- **Package signatures are still verified by NuGet**: packages are served byte
  for byte, and the repository-signature resource through the proxy.
- **Signature verification contacts the signing CAs.** To check that a
  signing certificate has not been revoked, NuGet asks the CA's revocation
  servers — `crl3.digicert.com` and `ocsp.digicert.com` for packages signed by
  nuget.org — which are not the proxy. Where they cannot be reached the restore
  still succeeds. To keep NuGet from asking:

  <!-- verified: lab:nuget -->

  ```sh
  export NUGET_CERT_REVOCATION_MODE=offline
  ```
- **The `dotnet` command reports usage to Microsoft** —
  `dc.services.visualstudio.com`, the one other host the lab saw it look up.
  To switch that off:

  <!-- verified: lab:nuget -->

  ```sh
  export DOTNET_CLI_TELEMETRY_OPTOUT=1
  ```
- **Search is not proxied.** The service index the proxy serves keeps the
  search resource pointing at nuget.org (it lives on another host), so IDE
  package search needs that host or fails; restore does not use it.
- **Publishing does not go through the proxy** (`dotnet nuget push`): it is
  read-only.
- **With a [personal cache link](../user-links.md)** the source belongs in your
  user-level `NuGet.Config`, not the repository's: the link works like a
  password.

## On the proxy

<!-- proxy-config -->

```yaml
upstreams:
  nuget:
    type: nuget
    url: https://api.nuget.org
```

The service index and registration documents are served live with their
same-host resources rewritten to the proxy (which is why `server.publicUrl`
must be set); `.nupkg` files are cached immutably. Details:
[backends: nuget](../backends.md#nuget).
