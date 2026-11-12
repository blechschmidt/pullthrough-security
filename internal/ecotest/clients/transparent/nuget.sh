#!/bin/sh
# nuget — restore from nuget.org, intercepted by the proxy.
set -eu
echo "ECOTEST_CLIENT_VERSION=$(dotnet --version)"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 NUGET_PACKAGES="$PWD/packages"

# No NuGet.config: nuget.org stays the package source. .NET trusts the proxy's
# CA through SSL_CERT_FILE; through a forward proxy it reads HTTPS_PROXY. The
# proxy moves the resources of the v3 service index onto api.nuget.org, so the
# flat-container (.nupkg) and registration requests are intercepted too.
export SSL_CERT_FILE="$PT_CA_CERT"

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
dotnet restore app.csproj
