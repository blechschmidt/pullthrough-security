# nuget fixture — how it was generated

`Fixture.Lib/packages.lock.json` was written by a real `dotnet restore` (2026-11-12, linux/amd64); it is not hand-made and must not be edited.

- Tool: .NET SDK 8.0.428, NuGet 6.11.2.1
- Image: `mcr.microsoft.com/dotnet/sdk:8.0` = `mcr.microsoft.com/dotnet/sdk@sha256:1b955f179b02df4f0eb5fadedaa898cbe44d620a64aab52eec72c8e91d1355b5`
- Package source: nuget.org (SDK default; no `nuget.config`)
- Inputs: `Fixture.Lib/Fixture.Lib.csproj` (`net8.0;netstandard2.0`, `RestorePackagesWithLockFile`, Newtonsoft.Json 13.0.3, Serilog 4.0.1, ProjectReference to Fixture.Core) and `Fixture.Core/Fixture.Core.csproj` (netstandard2.0, no packages, lock file not enabled, so no `Fixture.Core/packages.lock.json` was written)

Command (restore only, no build):

    docker run --rm -v /mnt/HC_Volume_106716549/pt178/jvm:/work -w /work/nuget \
      -e NUGET_PACKAGES=/work/cache/nuget-packages -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
      mcr.microsoft.com/dotnet/sdk:8.0 \
      sh -c 'dotnet --version && dotnet nuget --version; dotnet restore Fixture.Lib/Fixture.Lib.csproj'

Notable features of `Fixture.Lib/packages.lock.json`:

- `"version": 1`; one section per target framework under `"dependencies"`.
- The framework keys are spelled differently: `".NETStandard,Version=v2.0"` (full name) and `"net8.0"` (short name).
- Three entry types: `Direct` (has `requested` range such as `"[13.0.3, )"`), `Transitive` (no `requested`), `Project`.
- Project entry `"fixture.core": {"type": "Project"}`: lower-cased project name, no version, no hash, no dependencies.
- `NETStandard.Library` 2.0.3 is `Direct` in the netstandard2.0 section although no csproj names it (implicit SDK reference); it is absent from net8.0.
- The same package differs per framework: Serilog 4.0.1 depends on System.Diagnostics.DiagnosticSource + System.Threading.Channels for netstandard2.0, on nothing for net8.0.
- netstandard2.0 has 11 packages (3 Direct, 8 Transitive), net8.0 has 2 (both Direct), plus the Project entry in each.
- Within a section, Direct entries come first, then Transitive, then Project.
- Inner `"dependencies"` values are declared minimums, not resolved versions: System.Memory asks for System.Runtime.CompilerServices.Unsafe 4.5.3; the locked entry is 6.0.0.
- `contentHash` is base64 SHA-512. For all 11 packages (all nuget.org-signed, they contain `.signature.p7s`) it equals the `contentHash` in the cache's `.nupkg.metadata` and does NOT equal base64(SHA-512) of the downloaded `.nupkg` bytes (that value is in the cache's `<id>.<version>.nupkg.sha512`).
- LF line endings, 2-space indent, no trailing newline at end of file.
