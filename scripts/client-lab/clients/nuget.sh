#!/bin/sh
# lab: client=NuGet (dotnet)
# lab: image=mcr.microsoft.com/dotnet/sdk:8.0
# lab: modes=open
#
# NuGet with the proxy as its only package source. (NuGet cannot present a
# token to the proxy; see nuget-token.sh.)
set -eu
echo "LAB_CLIENT_VERSION=$(dotnet --version)"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
# NuGet verifies package signatures and, for that, asks the signing CAs'
# revocation servers (crl3.digicert.com, ocsp.digicert.com for nuget.org's
# packages). "offline" keeps that check to what is cached locally.
export NUGET_CERT_REVOCATION_MODE=offline

# .NET on Linux reads the CA bundle from SSL_CERT_FILE.
export SSL_CERT_FILE=/etc/ssl/corp-ca.pem

cat > NuGet.config <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="proxy" value="https://proxy.example.com/v1/nuget/v3/index.json" />
  </packageSources>
</configuration>
EOF

cat > app.csproj <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" />
  </ItemGroup>
</Project>
EOF
dotnet restore app.csproj
test -d ~/.nuget/packages/newtonsoft.json/13.0.3

# packages.lock.json records versions and content hashes, not the source.
! grep -q 'proxy.example.com' packages.lock.json
dotnet nuget list source | grep -q "https://proxy.example.com/v1/nuget/v3/index.json"
