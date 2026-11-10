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
