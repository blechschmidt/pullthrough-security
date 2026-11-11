#!/bin/sh
# lab: client=NuGet (with a token: refused)
# lab: image=mcr.microsoft.com/dotnet/sdk:8.0
# lab: modes=auth
#
# A LIMITATION, asserted: NuGet sends the credentials of a package source only
# in answer to a Basic challenge, and the proxy challenges with Bearer. The
# restore fails with 401.
set -eu
echo "LAB_CLIENT_VERSION=$(dotnet --version)"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
# NuGet verifies package signatures and, for that, asks the signing CAs'
# revocation servers (crl3.digicert.com, ocsp.digicert.com for nuget.org's
# packages). "offline" keeps that check to what is cached locally.
export NUGET_CERT_REVOCATION_MODE=offline
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem

cat > NuGet.config <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="proxy" value="https://proxy.example.com/v1/nuget/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <proxy>
      <add key="Username" value="pullthrough" />
      <add key="ClearTextPassword" value="${PROXY_TOKEN}" />
    </proxy>
  </packageSourceCredentials>
</configuration>
EOF

cat > app.csproj <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" />
  </ItemGroup>
</Project>
EOF
if dotnet restore app.csproj >restore.log 2>&1; then
    echo "NuGet restored with a token: the limitation is gone — update docs/clients/nuget.md"
    cat restore.log; exit 1
fi
cat restore.log
grep -q "NU1301" restore.log
